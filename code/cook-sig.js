/*!
 * cook-sig - Generats signature examples
 *
 * This content is in the public domain.
 */

var jose = require("jose"),
    Q = require("q"),
    fs = require("fs"),
    common = require("./common.js");

var keys = fs.readFileSync(__dirname + "/../pki/signatures.json", "utf8");
keys = JSON.parse(keys);
keys = jose.JWK.asKeyStore(keys);

var input = "It’s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there’s no knowing where you might be swept off to.";

var ops = [
    {
        name: "RSA v1.5 Signature",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"RSA"}),
                protect: "*",
                header: {
                    alg: "RS256"
                }
            }
        ]
    },
    {
        name: "RSA-PSS Signature",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"RSA"}),
                protect: "*",
                header: {
                    alg: "PS384"
                }
            }
        ]
    },
    {
        name: "ECDSA Signature",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"EC"}),
                protect: "*",
                header: {
                    alg: "ES512"
                }
            }
        ]
    },
    {
        name: "HMAC-SHA2 Integrity Protection",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"oct"}),
                protect: "*",
                header: {
                    alg: "HS256"
                }
            }
        ]
    },
    {
        name: "Detached Signature",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"oct"}),
                protect: "*",
                header: {
                    alg: "HS256"
                }
            }
        ],
        post: function(jws) {
            delete jws.payload;
            
            return jws;
        }
    },
    {
        name: "Protecting Specific Header Fields",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"oct"}),
                protect: "alg",
                header: {
                    alg: "HS256"
                }
            }
        ]
    },
    {
        name: "Protecting Content Only",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"oct"}),
                protect: null,
                header: {
                    alg: "HS256"
                }
            }
        ]
    },
    {
        name: "Multiple Signatures",
        payload: input,
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({"kty":"RSA"}),
                protect: "alg",
                header: {
                    alg: "RS256"
                }
            },
            {
                key: keys.get({"kty":"EC"}),
                protect: null,
                header: {
                    alg: "ES512"
                }
            },
            {
                key: keys.get({"kty":"oct"}),
                protect: "*",
                header: {
                    alg: "HS256"
                }
            }
        ]
    }
]

var doOp = function(op) {
    var sig,
        results;
    
    sig = jose.JWS.createSign(op.opts, op.signers);
    sig.update(op.payload, "utf8");
    results = sig.final();
    
    if (op.post) {
        results = results.then(op.post);
    }
    
    results = results.then(function(jws) {
        console.log("Example '%s:'", op.name);
        console.log("==============================================================");

        
        var compact, json;
        compact = common.makeCompact(jws);
        json = common.prettify(jws);
        
        var __outputSig = function(idx) {
            var key = op.signers[idx].key;
            key = common.prettify(key.toJSON(true));
            console.log("\nSignature #%d Key:",
                        idx+1);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(key);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    
            var header;
            header = jws.signatures[idx].protected;
            if (header) {
                header = {
                    b64u: common.prettify(header),
                    json: common.prettify(JSON.parse(jose.base64url.decode(header, "utf8")))
                };
                console.log("\nSignature #%d Protected JWS Header (JSON):", idx+1);
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                console.log(header.json);
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                console.log("\nSignature #%d Protected JWS Header (base64url):", idx+1);
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                console.log(header.b64u);
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            }
        
            header = jws.signatures[idx].header;
            if (header) {
                header = common.prettify(header);
                console.log("\nSignature #%d Unprotected JWS Header (JSON):\n", idx+1);
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                console.log(header);
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            }
        
            var sig = jws.signatures[idx].signature;
            sig = common.prettify(sig);
            console.log("\nSignature #%d:", idx+1);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(sig);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            
            console.log("\nSignature #%d JSON:", idx+1);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(common.prettify(jws.signatures[idx]));
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        }
        for (var idx = 0; idx < op.signers.length; idx++) {
            __outputSig(idx);
        }
        
        if (compact.length) {
            compact = compact.map(chunk).
                              map(function(v) {
                                if (!v) {
                                    return "\n";
                                } else {
                                    return "\n" + v + "\n"
                                }
                              }).
                              join(".").
                              trim();
            console.log("\nCompact Serialization:");
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(compact);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        }
        
        console.log("\nJSON Serialization:");
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log(json);
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log("==============================================================");
        console.log("\n\n");
    }, function(err) {
        console.log("Example '%s' failed: %s", op.name, err.message);
    });
    
    return op;
}

console.log("\nPayload (utf-8):");
console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
console.log(common.splitit(input));
console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
console.log("\nPayload (base64url):");
console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
console.log(common.prettify(jose.base64url.encode(input, "utf8")));
console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
console.log("==============================================================");
console.log("\n\n");

ops.reduce(function(chain, op) {
    return chain.then(function() {
        return doOp(op);
    });
}, Q.resolve());
