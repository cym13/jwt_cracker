import std.stdio;
import std.array;
import std.digest.sha;
import std.digest.hmac;
import std.base64;
import std.string;
import std.parallelism;
import std.json;
import std.exception: basicExceptionCtors;
import std.conv;

alias B64 = Base64Impl!('-', '_', Base64.NoPadding);
alias HashAlg = void function(const(ubyte)[], const(ubyte)[], ubyte[]);

struct MacAlgorithm {
    string  hashId;
    size_t  size;
    HashAlg digest;
}

MacAlgorithm HS256 = MacAlgorithm("HS256", 256/8,
        function void(const(ubyte)[] data, const(ubyte)[] secret, ubyte[] result) {
            result[] = hmac!SHA256(data, secret);
        });

MacAlgorithm HS384 = MacAlgorithm("HS384", 384/8,
        function void(const(ubyte)[] data, const(ubyte)[] secret, ubyte[] result) {
            result[] = hmac!SHA384(data, secret);
        });

MacAlgorithm HS512 = MacAlgorithm("HS512", 512/8,
        function void(const(ubyte)[] data, const(ubyte)[] secret, ubyte[] result) {
            result[] = hmac!SHA512(data, secret);
        });

static class JwtException : Exception { mixin basicExceptionCtors; }

struct Jwt {
    ubyte[] header;
    ubyte[] payload;
    ubyte[] mac;

    static Jwt decode(in string token) {
        Jwt result = Jwt.init;

        auto parts = token.split(".");
        result.header  = B64.decode(parts[0]);
        result.payload = B64.decode(parts[1]);
        result.mac     = B64.decode(parts[2]);

        return result;
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
        auto alg  = this.algorithm;
        auto data = B64.encode(header) ~ "." ~ B64.encode(payload);
        return this.check(alg, cast(ubyte[])data, secret);
    }

    bool check(in ubyte[] data, in ubyte[] secret) const {
        auto alg = this.algorithm;
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

        auto decodedHeader = parseJSON((cast(char[])header).byCodeUnit
                                                           .to!string);

        switch (decodedHeader["alg"].str) {
            case "HS256":
                return HS256;
            case "HS384":
                return HS384;
            case "HS512":
                return HS512;
            default:
                throw new JwtException("Algorithm not supported: " ~
                                        decodedHeader["alg"].str);
        }
    }

    string toString() const {
        return cast(string) (B64.encode(header)  ~ "."
                           ~ B64.encode(payload) ~ "."
                           ~ B64.encode(mac));
    }
}

bool dictionaryTest(in Jwt token, in string[] candidates, out string result) {
    auto data = B64.encode(token.header) ~ "." ~ B64.encode(token.payload);
    auto alg  = token.algorithm;

    auto numTasks = totalCPUs * 5;
    auto taskpool = new TaskPool(numTasks);

    ubyte[][] buffers;
    foreach (i ; 0 .. numTasks+1)
        buffers ~= new ubyte[alg.size];

    bool found = false;
    foreach(candidate ; taskpool.parallel(candidates)) {
        if (token.check(alg,
                        cast(ubyte[])data,
                        cast(ubyte[])candidate.representation,
                        buffers[taskpool.workerIndex]))
        {
            result = candidate;
            found = true;
            taskpool.stop;
        }
    }
    taskpool.finish();
    return found;
}

void main(string[] args) {
    if (args.length == 1) {
        writeln(Jwt.encode(HS512, "{\"name\":\"tommy\"}",
                    "itsasecret".representation).toString);
        return;
    }

    Jwt token = Jwt.decode(args[1]);
    string dicFilename = args[2];

    File dicFile;
    if (dicFilename == "-") {
        dicFile = stdin;
    }
    else {
        dicFile = File(dicFilename, "rb");
    }

    string[] candidates = dicFile.byLineCopy(KeepTerminator.no).array;
    if (dicFile != stdin)
        dicFile.close;

    string result;
    if (dictionaryTest(token, candidates, result))
        writeln("Found: ", result);
    else
        writeln("No solution found");
}
