
var jose = require("jose"),
    Q = require("q"),
    fs = require("fs");

var keys = fs.readFileSync(__dirname + "/../pki/signatures.json", "utf8");
keys = JSON.parse(keys);
keys = jose.JWK.asKeyStore(keys);

var input = "It’s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there’s no knowing where you might be swept off to.";

var chunk = function(str) {
    var segments = Math.ceil(str.length / 64);
    var results = [],
        seglen,
        idx;
    for (idx = 1; idx <= segments; idx++) {
        seglen = idx * 64;
        results.push(str.substring(seglen - 64, seglen));
    }
    
    return results.join("\n");
}
var splitit = function(str) {
    var results = [],
        line,
        pos;
    
    while (str.length) {
        if (str.length < 64) {
            pos = -1;
        } else {
            pos = str.lastIndexOf(" ", 64);
        }
        
        if (pos === -1) {
            line = str;
            str = "";
        } else {
            line = str.substring(0, pos);
            str = str.substring(pos);
        }
        results.push(line);
    }
    
    return results.join("\n");
}

var prettify = function(input) {
    var str;
    if (typeof(input) === "string") {
        str = input.trim();
    } else {
        str = JSON.stringify(input, null, 2);
    }
    str = str.split("\n").
              map(chunk).
              join("\n");
    
    return str;
}

var makeCompact = function(json) {
    var jws = [];
    
    if (typeof(json) === "string") {
        jws = json.split(".");
    } else {
        if (json.signatures.length > 1) {
            return [];
        }
        if (json.signatures[0].header) {
            return [];
        }
    
        jws[0] = json.signatures[0].protected || "";
        jws[1] = json.payload || "";
        jws[2] = json.signatures[0].signature || "";
    }
    
    return jws;
}

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
                    alg: "PS256"
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
                protect: "*",
                header: {
                    alg: "RS256"
                }
            },
            {
                key: keys.get({"kty":"EC"}),
                protect: "*",
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
        console.log("================================================================");

        
        var compact, json;
        compact = makeCompact(jws);
        json = prettify(jws);
        
        var __outputSig = function(idx) {
            var key = op.signers[idx].key;
            key = prettify(key.toJSON(true));
            console.log("\nSignature #%d Key:",
                        idx+1);
            console.log("----------------------------------------------------------------");
            console.log(key);
            console.log("----------------------------------------------------------------");
    
            var header;
            header = jws.signatures[idx].protected;
            if (header) {
                header = {
                    b64u: prettify(header),
                    json: prettify(JSON.parse(jose.base64url.decode(header, "utf8")))
                };
                console.log("\nSignature #%d protected JWS Header (JSON):", idx+1);
                console.log("----------------------------------------------------------------");
                console.log(header.json);
                console.log("----------------------------------------------------------------");
                console.log("\nSignature #%d protected JWS Header (base64url):", idx+1);
                console.log("----------------------------------------------------------------");
                console.log(header.b64u);
                console.log("----------------------------------------------------------------");
            }
        
            header = jws.signatures[idx].header;
            if (header) {
                header = prettify(header);
                console.log("\nSignature #%d unprotected JWS Header (JSON):\n%s", idx+1);
                console.log("----------------------------------------------------------------");
                console.log(header);
                console.log("----------------------------------------------------------------");
            }
        
            var sig = jws.signatures[idx].signature;
            sig = prettify(sig);
            console.log("\nSignature #%d:", idx+1);
            console.log("----------------------------------------------------------------");
            console.log(sig);
            console.log("----------------------------------------------------------------");
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
            console.log("\nCompact serialization:");
            console.log("----------------------------------------------------------------");
            console.log(compact);
            console.log("----------------------------------------------------------------");
        }
        
        console.log("\nJSON serialization:");
        console.log("----------------------------------------------------------------");
        console.log(json);
        console.log("----------------------------------------------------------------");
        console.log("================================================================");
        console.log("\n\n");
    }, function(err) {
        console.log("Example '%s' failed: %s", op.name, err.message);
    });
    
    return op;
}

console.log("\nPayload (utf-8):");
console.log("----------------------------------------------------------------");
console.log(splitit(input));
console.log("----------------------------------------------------------------");
console.log("\nPayload (base64url):");
console.log("----------------------------------------------------------------");
console.log(prettify(jose.base64url.encode(input, "utf8")));
console.log("----------------------------------------------------------------");
console.log("================================================================");
console.log("\n\n");

ops.reduce(function(chain, op) {
    return chain.then(function() {
        return doOp(op);
    });
}, Q.resolve());
