import std.stdio;
import std.algorithm;
import std.range;
import std.array;
import std.digest.sha;
import std.digest.hmac;
import std.base64;
import std.string;
import std.parallelism;
import std.json;
import std.exception: basicExceptionCtors;
import std.conv;

immutable helpMsg =
"Optimized JWT HMAC cracker

Usage: jwt_cracker [options] JWT
       jwt_cracker [options] -H HEADER -P payload -S secret
       jwt_cracker [options] -d DIC JWT
       jwt_cracker [options] (-B|-b ALPH) -l LENGTH JWT

Arguments:
    JWT     JWT to crack. Without any option, parses the JWT and prints it.
            jwt_cracker supports 3 sets of options for 3 different
            operations: encoding, dictionary attack and bruteforce attack.
            Specifying multiple sets of options at once resolves them in the
            order shown above.

Options:
    -h, --help                  Print this help and exit
    -v, --version               Print version and exit

    -H, --header HEADER         Header to encode JWT
    -P, --payload PAYLOAD       Payload to encode JWT
    -S, --secret SECRET         Secret to encode JWT

    -d, --dictionary DIC        Perform dictionary attack with file DIC
                                Use - to read from stdin

    -b, --bruteforce ALPH       Perform bruteforce attack with alphabet
    -B, --default-bruteforce    Perform bruteforce attack with default alphabet
                                Default: " ~ DEFAULT_ALPHABET ~ "
    -l, --length LENGTH         Minimum length for bruteforce attack
                                If it contains a dash, acts as a min-max range
                                Eg: 0-7 means 0 to 7 characters long.
                                    3-  means 3 to infinity
";

immutable vernum="1.0.0";

alias B64 = Base64Impl!('-', '_', Base64.NoPadding);
alias HashAlg = void function(const(ubyte)[], const(ubyte)[], ubyte[]);

struct MacAlgorithm {
    string  hashId;
    size_t  size;
    HashAlg digest;
}

template HSTemplate(string sz) {
    enum HSTemplate = `
        MacAlgorithm HS` ~ sz ~ ` = MacAlgorithm("HS` ~ sz ~ `", ` ~ sz ~ `/8,
        function void(const(ubyte)[] data,
                      const(ubyte)[] secret,
                      ubyte[] result)
        {
            result[] = hmac!SHA` ~ sz ~ `(data, secret);
        });
    `;
}

mixin(HSTemplate!"224");
mixin(HSTemplate!"256");
mixin(HSTemplate!"384");
mixin(HSTemplate!"512");

static class JwtException : Exception { mixin basicExceptionCtors; }

struct Jwt {
    ubyte[] header;
    ubyte[] payload;
    ubyte[] mac;

    static Jwt decode(in string token) {
        Jwt result = Jwt.init;

        immutable parts = token.split(".");
        result.header  = B64.decode(parts[0]);
        result.payload = B64.decode(parts[1]);
        result.mac     = B64.decode(parts[2]);

        return result;
    }

    static Jwt encode(in string header, in string payload, in ubyte[] secret) {
        import std.utf: byCodeUnit;

        immutable decodedHeader = parseJSON((cast(char[])header).byCodeUnit
                                                                .to!string);
        immutable alg = Jwt.algorithm(decodedHeader["alg"].str);
        return Jwt.encode(alg, payload, secret);
    }

    static Jwt encode(in MacAlgorithm alg, in string payload, in ubyte[] secret) {
        Jwt result = Jwt.init;

        result.header  = cast(ubyte[]) ("{\"alg\":\""
                                       ~ alg.hashId
                                       ~ "\",\"typ\":\"JWT\"}").representation;

        result.payload = cast(ubyte[]) payload.representation;

        char[] data = B64.encode(result.header)
                    ~ "."
                    ~ B64.encode(result.payload);

        result.mac =  new ubyte[alg.size];
        alg.digest(cast(ubyte[])data, secret, result.mac);

        return result;
    }

    bool check(in ubyte[] secret) const {
        immutable alg  = this.algorithm;
        auto data = B64.encode(header) ~ "." ~ B64.encode(payload);
        return this.check(alg, cast(ubyte[])data, secret);
    }

    bool check(in ubyte[] data, in ubyte[] secret) const {
        immutable alg = this.algorithm;
        return check(alg, data, secret);
    }

    bool check(in MacAlgorithm alg, in ubyte[] data, in ubyte[] secret) const {
        ubyte[] buf = new ubyte[alg.size];
        return check(alg, data, secret, buf);
    }

    bool check(in MacAlgorithm alg, in ubyte[] data, in ubyte[] secret, ref ubyte[] buf) const {
        alg.digest(data, secret, buf);
        return buf == mac;
    }

    MacAlgorithm algorithm() const {
        import std.utf: byCodeUnit;

        immutable decodedHeader = parseJSON((cast(char[])header).byCodeUnit
                                                                .to!string);

        return Jwt.algorithm(decodedHeader["alg"].str);
    }

    static MacAlgorithm algorithm(string alg) {
        switch (alg) {
            case "HS224":
                return HS224;
            case "HS256":
                return HS256;
            case "HS384":
                return HS384;
            case "HS512":
                return HS512;
            default:
                throw new JwtException("Algorithm not supported: " ~ alg);
        }
    }

    string toString() const {
        return (B64.encode(header)  ~ "." ~
                B64.encode(payload) ~ "." ~
                B64.encode(mac)).to!string;
    }

    string parse() const {
        import std.format;
        import std.ascii;

        return format("Header: %s%sPayload: %s%sSignature: %s",
                      cast(char[])header, newline,
                      cast(char[])payload, newline,
                      mac.toHexString);
    }
}

bool dictionaryTest(in Jwt token, in string[] candidates, out string result) {
    // 5 seems good, the tasks are work intensive so there's no point in
    // making too many, but there is some gain in not having as many as the
    // number of CPUs
    immutable numTasks = totalCPUs * 5;
    immutable tokenAlgorithm = token.algorithm;

    // Allocate one buffer per task to avoid allocations in the loop and
    // sharing state between parallel tasks
    ubyte[][] buffers;
    foreach (i ; 0 .. numTasks+1)
        buffers ~= new ubyte[tokenAlgorithm.size];

    auto data = B64.encode(token.header) ~ "." ~ B64.encode(token.payload);

    bool found = false;
    auto taskpool = new TaskPool(numTasks);
    foreach(candidate ; taskpool.parallel(candidates)) {
        if (token.check(tokenAlgorithm,
                        cast(ubyte[])data,
                        cast(ubyte[])candidate.representation,
                        buffers[taskpool.workerIndex]))
        {
            result = candidate;
            found = true;
            taskpool.stop;
        }
    }

    taskpool.finish;
    return found;
}

struct BruteforceGenerator {
    const char[] alphabet;
    const size_t len;
    char[] buffer;
    uint[] bufferIdx;
    ulong  remaining;

    this(in char[] alphabet_, in size_t len_) {
        alphabet = alphabet_;
        len      = len_;

        buffer    = new char[len];
        bufferIdx = new uint[len];

        buffer[] = alphabet[0];
        bufferIdx[] = 0;

        remaining = alphabet.length ^^ len;
    }

    bool empty() const {
        return remaining == 0;
    }

    ref char[] front() {
        return buffer;
    }

    void popFront() {
        if (--remaining == 0)
            return;

        size_t toChangeIdx = len-1;

        while (bufferIdx[toChangeIdx] == alphabet.length - 1) {
            toChangeIdx--;
        }

        bufferIdx[toChangeIdx] += 1;
        buffer[toChangeIdx] = alphabet[bufferIdx[toChangeIdx]];

        for (size_t i=toChangeIdx+1 ; i<len ; i++) {
            bufferIdx[i] = 0;
            buffer[i] = alphabet[0];
        }

    }

    size_t length() {
        return alphabet.length ^^ len;
    }
}

// 74% of leaked secrets contain only characters in this set
immutable DEFAULT_ALPHABET = "ae1ionrls0t2mc8uhyb93pgk5467vfj";

bool bruteforceTest(in Jwt token,
                    in char[] alphabet,
                    in size_t minlen,
                    in size_t maxlen,
                    out string result)
{
    for (size_t i=minlen ; i<maxlen+1 ; i++)
        if (bruteforceTest(token, alphabet, i, result))
            return true;
    return false;
}

bool bruteforceTest(in Jwt token,
                    in char[] alphabet,
                    in size_t len,
                    out string result)
{
    // 5 seems good, the tasks are work intensive so there's no point in
    // making too many, but there is some gain in not having as many as the
    // number of CPUs
    immutable numTasks = totalCPUs * 5;
    immutable tokenAlgorithm = token.algorithm;

    // Allocate one buffer per task to avoid allocations in the loop and
    // sharing state between parallel tasks
    ubyte[][] buffers;
    foreach (i ; 0 .. numTasks+1)
        buffers ~= new ubyte[tokenAlgorithm.size];

    auto data = B64.encode(token.header) ~ "." ~ B64.encode(token.payload);

    bool found = false;

    auto bruteforceRange = BruteforceGenerator(alphabet, len);

    size_t chunkSize = 100000;
    char[][] candidates = [];
    foreach (i ; 0 .. chunkSize) {
        candidates ~= new char[len];
    }

    auto taskpool = new TaskPool(numTasks);
    while (!bruteforceRange.empty && !found) {
        for (size_t i=0 ; i<chunkSize && !bruteforceRange.empty ; i++) {
            candidates[i][] = bruteforceRange.front[];
            bruteforceRange.popFront;
        }

        foreach(candidate ; taskpool.parallel(candidates)) {
            if (token.check(tokenAlgorithm,
                            cast(ubyte[])data,
                            cast(ubyte[])candidate,
                            buffers[taskpool.workerIndex]))
            {
                result = candidate.to!string;
                found = true;
                taskpool.stop;
            }
        }
    }

    taskpool.finish;
    return found;
}

bool readable(string path) {
    import std.stdio: File;
    import std.exception: collectException;

    return collectException(File(path, "r")) is null;
}

int main(string[] args) {
    import std.getopt;

    bool   versionWanted;
    string headerToEncode;
    string payloadToEncode;
    string secretToEncode;
    string dictionaryPath;
    string bruteforceAlphabet;
    bool   useDefaultBruteforceAlphabet;
    string bruteforceLength;
    Jwt    jwtToCrack;

    bool shouldParseJwt = true;
    bool shouldEncodeJwt;
    bool shouldPerformDictionaryAttack;
    bool shouldPerformBruteforceAttack;

    try {
        auto arguments = getopt(args,
                std.getopt.config.bundling,
                std.getopt.config.caseSensitive,
                "v|version",            &versionWanted,
                "H|header",             &headerToEncode,
                "P|payload",            &payloadToEncode,
                "S|secret",             &secretToEncode,
                "d|dictionary",         &dictionaryPath,
                "b|bruteforce",         &bruteforceAlphabet,
                "B|default-bruteforce", &useDefaultBruteforceAlphabet,
                "l|length",             &bruteforceLength,
        );

        if (arguments.helpWanted) {
            write(helpMsg);
            return 0;
        }
        if (versionWanted) {
            writeln(vernum);
            return 0;
        }

        // "-" has the special meaning of stdin
        if (dictionaryPath != "" && dictionaryPath != "-"
                                 && !readable(dictionaryPath))
        {
            stderr.writeln("Unreadable file: ", dictionaryPath);
            return 1;
        }

        // We need either none or all of -H, -P and -S
        if (   (headerToEncode  != "" && (  payloadToEncode == ""
                                         || secretToEncode == ""))
            || (payloadToEncode != "" && (headerToEncode  == ""
                                         || secretToEncode == ""))
            || (secretToEncode  != "" && (headerToEncode  == ""
                                         || payloadToEncode == "")))
        {
            stderr.writeln("Error: --header, --payload or --secret missing");
            return 1;
        }

        if (bruteforceLength &&
            !(useDefaultBruteforceAlphabet || bruteforceAlphabet != ""))
        {
            stderr.writeln("Error: Length defined without bruteforce alphabet");
            return 1;
        }

        if ((useDefaultBruteforceAlphabet || bruteforceAlphabet != "") &&
            !bruteforceLength)
        {
            stderr.writeln("Error: Bruteforce alphabet defined without length");
            return 1;
        }

        if (headerToEncode != "") {
            shouldEncodeJwt = true;
            shouldParseJwt = false;
        }
        if (dictionaryPath != "") {
            shouldPerformDictionaryAttack = true;
            shouldParseJwt = false;
        }
        if (bruteforceLength != "") {
            shouldPerformBruteforceAttack = true;
            shouldParseJwt = false;
        }

    } catch (GetOptException ex) {
        stderr.write(helpMsg);
        return 1;
    }

    if (   shouldParseJwt
        || shouldPerformBruteforceAttack
        || shouldPerformDictionaryAttack)
    {
        if (args.length == 1) {
            stderr.writeln("Missing JWT. Use --help for help.");
            return 1;
        }
        if (args.length > 2) {
            stderr.writeln("Too many arguments");
            return 1;
        }

        jwtToCrack = Jwt.decode(args[1]);
    }

    if (shouldParseJwt) {
        jwtToCrack.parse.writeln;
        return 0;
    }

    if (shouldEncodeJwt) {
        Jwt encodedJwt;
        try {
            encodedJwt = Jwt.encode(headerToEncode,
                                    payloadToEncode,
                                    secretToEncode.representation);
        } catch (JwtException e) {
            writeln(e.msg);
            return 1;
        }

        writeln("Encoded: ", encodedJwt);
    }

    if (!shouldPerformDictionaryAttack && !shouldPerformBruteforceAttack)
        return 0;

    // Checks that the algorithm is supported
    try {
        jwtToCrack.algorithm;
    } catch (JwtException e) {
        stderr.writeln(e.msg);
        return 1;
    }

    bool found = false;
    string result;

    if (shouldPerformDictionaryAttack) {
        File dicFile;
        if (dictionaryPath == "-")
            dicFile = stdin;
        else
            dicFile = File(dictionaryPath, "rb");

        // Load all candidates in memory
        // This makes it easier to divide up the tasks for parallel processing
        string[] candidates = dicFile.byLineCopy(KeepTerminator.no).array;
        if (dicFile != stdin)
            dicFile.close;

        writeln("[+] Dictionary attack");
        if (dictionaryTest(jwtToCrack, candidates, result))
            found = true;
    }

    if (shouldPerformBruteforceAttack && !found) {
        // Inefficient but alphabets are expected to be short and we want to
        // keep the order as that allows frequency optimization
        char[] alphabet = [];

        if (useDefaultBruteforceAlphabet) {
            alphabet = cast(char[])DEFAULT_ALPHABET;
        }
        else {
            foreach (c ; cast(char[]) bruteforceAlphabet)
                if (!alphabet.canFind(c))
                    alphabet ~= c;
        }

        size_t minLength;
        size_t maxLength;

        if (!bruteforceLength.canFind("-")) {
            minLength = bruteforceLength.to!size_t;
            maxLength = minLength + 1;
        } else {
            string[] parts = bruteforceLength.split("-").array;

            minLength = parts[0] != "" ? parts[0].to!size_t     : 0;
            maxLength = parts[1] != "" ? parts[1].to!size_t + 1 : size_t.max;
        }

        for (size_t len=minLength ; len < maxLength ; len++) {
            writeln("[+] Bruteforcing length ", len);
            if (bruteforceTest(jwtToCrack, alphabet, len, result)) {
                found = true;
                break;
            }
        }
    }

    if (found)
        writeln("Found: ", result);
    else
        writeln("No solution found");

    return 0;
}
