/*!
 * cook-enc - Generats encryption examples
 *
 * This content is in the public domain.
 */

var jose = require("jose"),
    $ = require("cloneextend"),
    Q = require("q"),
    fs = require("fs"),
    util = require("util"),
    zlib = require("zlib"),
    common = require("./common.js");

var keys = fs.readFileSync(__dirname + "/../pki/encryption.json", "utf8");
keys = JSON.parse(keys);
keys = jose.JWK.asKeyStore(keys);

var inputs = {
    common: "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.",
    "jwk-set+json": fs.readFileSync(__dirname + "/../pki/shared.json", "utf8")
}
inputs["jwk-set+json"] = JSON.stringify(JSON.parse(inputs["jwk-set+json"]))

var ops = {
    "rsa15": {
        name: "RSA 1.5 and AES-HMAC-SHA2",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128CBC-HS256",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty:"RSA",
                    kid:"frodo.baggins@hobbiton.example"
                }),
                header: {
                    alg: "RSA1_5"
                }
            }
        ],
        plaintext: "common"
    },
    "rsa_oaep": {
        name: "RSA-OAEP and AES-GCM",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A256GCM",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty:"RSA",
                    kid:"samwise.gamgee@hobbiton.example"
                }),
                header: {
                    alg: "RSA-OAEP"
                }
            }
        ],
        plaintext: "common"
    },
    "pbes2": {
        name: "PBES2-AES-KeyWrap and AES-CBC-HMAC-SHA2",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128CBC-HS256",
            protect: "*",
            fields: {
                cty: "jwk-set+json"
            }
        },
        recipients: [
            {
                key: jose.JWK.asKey({
                    alg: "PBES2-HS256+A128KW",
                    k:jose.base64url.encode("entrap_o_peter_long_credit_tun", "utf8")
                }),
                header: {
                    alg: "PBES2-HS256+A128KW",
                    p2s: "8Q1SzinasR3xchYz6ZZcHA",
                    p2c: 8192
                },
                reference: null
            }
        ],
        plaintext: "jwk-set+json"
    },
    "ecdh_aeskw": {
        name: "ECDH-ES with AES KeyWrap and AES-GCM",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128GCM",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "EC",
                    kid: "peregrin.took@tuckborough.example"
                }),
                header: {
                    alg: "ECDH-ES+A128KW"
                }
            }
        ],
        plaintext: "common"
    },
    "ecdh": {
        name: "ECDH-ES and AES-CBC-HMAC-SHA2",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128CBC-HS256",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "EC",
                    kid: "meriadoc.brandybuck@buckland.example"
                }),
                header: {
                    alg: "ECDH-ES"
                }
            }
        ],
        plaintext: "common"
    },
    "dir_gcm": {
        name: "direct AES-GCM",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128GCM",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "77c7e2b8-6e13-45cf-8672-617b5b45243a"
                }),
                header: {
                    alg: "dir"
                }
            }
        ],
        plaintext: "common"
    },
    "aesgcmkw": {
        name: "AES-GCM KeyWrap and AES-CBC-HMAC-SHA2",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128CBC-HS256",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d"
                }),
                header: {
                    alg: "A256GCMKW"
                }
            }
        ],
        plaintext: "common"
    },
    "aeskw": {
        name: "AES KeyWrap and AES-GCM",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128GCM",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "81b20965-8332-43d9-a468-82160ad91ac8"
                }),
                header: {
                    alg: "A128KW"
                }
            }
        ],
        plaintext: "common"
    },
    "compressed": {
        name: "Compressed Content",
        opts: {
            zip: true,
            compact: false,
            contentAlg: "A128GCM",
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "81b20965-8332-43d9-a468-82160ad91ac8"
                }),
                header: {
                    alg: "A128KW"
                }
            }
        ],
        plaintext: "common"
    },
    "aad": {
        name: "Including Additional Authenticated Data",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128GCM",
            aad: jose.utf8.encode('["vcard",[["version",{},"text","4.0"],["fn",{},"text","Meriadoc Brandybuck"],["n",{},"text",["Brandybuck","Meriadoc","Mr.",""]],["bday",{},"text","TA 2982"],["gender",{},"text","M"]]]'),
            protect: "*"
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "81b20965-8332-43d9-a468-82160ad91ac8"
                }),
                header: {
                    alg: "A128KW"
                }
            }
        ],
        plaintext: "common"
    },
    "somefields": {
        name: "Protecting Specific Header Fields",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128GCM",
            protect: "enc",
            fields: {
                alg: "A128KW",
                kid: "81b20965-8332-43d9-a468-82160ad91ac8"
            }
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "81b20965-8332-43d9-a468-82160ad91ac8"
                })
            }
        ],
        plaintext: "common"
    },
    "nofields": {
        name: "Protect Content Only",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128GCM",
            protect: null,
            fields: {
                alg: "A128KW",
                kid: "81b20965-8332-43d9-a468-82160ad91ac8"
            }
        },
        recipients: [
            {
                key: keys.get({
                    kty: "oct",
                    kid: "81b20965-8332-43d9-a468-82160ad91ac8"
                })
            }
        ],
        plaintext: "common"
    },
    "multi": {
        name: "Multiple Recipients",
        opts: {
            zip: false,
            compact: false,
            contentAlg: "A128CBC-HS256",
            protect: "enc",
            fields: {
                cty: "text/plain"
            }
        },
        recipients: [
            {
                key: keys.get({
                    kty: "RSA",
                    kid: "frodo.baggins@hobbiton.example"
                }),
                header: {
                    alg: "RSA1_5"
                }
            },
            {
                key: keys.get({
                    kty: "EC",
                    kid: "peregrin.took@tuckborough.example"
                }),
                header: {
                    alg: "ECDH-ES+A256KW"
                }
            },
            {
                key: keys.get({
                    kty: "oct",
                    kid: "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d"
                }),
                header: {
                    alg: "A256GCMKW"
                }
            }
        ],
        plaintext: "common"
    }
};


var doOp = function(op) {
    if (op.opts.aad) {
        var aad = op.opts.aad;
        console.log("\nAdditional Authenticated Data (JSON):");
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log(common.prettify(JSON.parse(aad)));
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log("\nAdditional Authenticated Data (base64url):");
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log(common.prettify(jose.base64url.encode(aad, "utf8")));
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    }

    var enc = jose.JWE.createEncrypt(op.opts, op.recipients);
    enc.update(inputs[op.plaintext], "utf8");
    
    var results = enc.final();
    results = results.then(function(jwe) {
        var compact = [], json;
        compact = common.makeCompactJWE(jwe);
        json = common.prettify(jwe);
    
        console.log("\nExample '%s'", op.name);
        console.log("==============================================================");
        
        // assemble common properties
        var hlogs = [];
        var cprops = {};
        if (jwe.unprotected) {
            hlogs.push(util.format("\nJWE Unprotected Header (JSON):"));
            hlogs.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            hlogs.push(util.format(common.prettify(jwe.unprotected)));
            hlogs.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            cprops = $.extend(cprops, jwe.unprotected);
        }
        if (jwe.protected) {
            var pheader;
            pheader = jose.base64url.decode(jwe.protected, "utf8");
            pheader = JSON.parse(pheader);

            hlogs.push(util.format("\nJWE Protected Header (JSON):"));
            hlogs.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            hlogs.push(util.format(common.prettify(pheader)));
            hlogs.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            hlogs.push(util.format("\nJWE Protected Header (base64url):"));
            hlogs.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            hlogs.push(util.format(common.prettify(jwe.protected)));
            hlogs.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            cprops = $.extend(cprops, pheader);
        }
        
        var cek;
        var __outputRcpt = function(rcpt, idx) {
            var log = [];
        
            var key = op.recipients[idx].key;
            if ((key.get("alg") || "").indexOf("PBES2-") === 0) {
                key = key.get("k", true);
            } else {
                key = common.prettify(key.toJSON(true));
            }
            log.push(util.format("\nRecipient #%d Key:", idx+1));
            log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            log.push(util.format(key));
            log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));

            // decrypt CEK
            var rprops = {};
            if (jwe.recipients && jwe.recipients[idx] && jwe.recipients[idx].header) {
                log.push(util.format("\nRecipient #%d Header (JSON):", idx+1));
                log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                log.push(util.format(common.prettify(jwe.recipients[idx].header)));
                log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                rprops = $.extend(rprops, jwe.recipients[idx].header);
            }
            rprops = $.extend(rprops, cprops);
            
            var encKey = jwe.recipients &&
                         jwe.recipients[idx] &&
                         jwe.recipients[idx].encrypted_key;
            if (encKey) {
                encKey = jose.base64url.decode(encKey, "binary");
            }
            
            var epk = op.recipients[idx].epk;
            if (epk) {
                epk = epk.toJSON(true, ["kid", "use", "alg"]);
                
                // log it separate
                log.push(util.format("\nRecipient #%d Ephemeral Public/Private Key (JSON):", idx+1));
                log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                log.push(util.format(common.prettify(epk)));
                log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
            
                // convert to binary
                rprops.epk.x = jose.base64url.decode(rprops.epk.x, "binary");
                rprops.epk.y = jose.base64url.decode(rprops.epk.y, "binary");
            }
            
            var key = op.recipients[idx].key;
            var unwrap = key.unwrap(rprops.alg,
                                    encKey,
                                    rprops);
            unwrap = unwrap.then(function(unwrapped) {
                cek = unwrapped.data;
                cek = jose.base64url.encode(cek, "binary");
                delete unwrapped.data;
                delete unwrapped.direct;
                delete unwrapped.once;
                
                var kprops = unwrapped.header || {};
                if (Object.keys(kprops).length) {
                    log.push(util.format("\nRecipient #%d Content Encryption Factors:", idx+1));
                    log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                    log.push(util.format(common.prettify(kprops)));
                    log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                }
                
                if (encKey) {
                    log.push(util.format("\nRecipient #%d JWE Encrypted Key:", idx+1));
                    log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                    log.push(util.format(common.prettify(jose.base64url.encode(encKey, "binary"))));
                    log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                }

                if (jwe.recipients && jwe.recipients[idx]) {
                    log.push(util.format("\nRecipient #%d:", idx+1));
                    log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                    log.push(util.format(common.prettify(jwe.recipients[idx])));
                    log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                }
                
                return log.join("\n");
            });
            
            return unwrap;
        }

        var results = Q.all(op.recipients.map(__outputRcpt));
        
        results.then(function(logs) {
            console.log("\nContent Encryption Key:");
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(common.prettify(cek));
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            
            if (jwe.iv) {
                console.log("\nInitialization Vector:");
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                console.log(common.prettify(jwe.iv));
                console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            }
            
            // output recipients
            console.log(logs.join("\n"));
            
            // output common headers
            console.log(hlogs.join("\n"));
            
            console.log("\nCiphertext:");
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(common.prettify(jwe.ciphertext));
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            
            console.log("\nAuthentication Tag:");
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(common.prettify(jwe.tag));
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            
            if (compact.length) {
                compact = compact.map(common.chunk).
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
        });
    });
    
    return results;
}

var exec = Array.prototype.slice.call(process.argv, 2);
if (!exec.length) {
    exec = Object.keys(ops);
}

var displayed = {},
    promise = Q.resolve();

// prepare operations, including logging plaintext to console
exec = exec.filter(function(opkey) {
    var op = ops[opkey];
    if (!op) {
        return false;
    }

    if (displayed[op.plaintext]) {
        return true;
    }
    displayed[op.plaintext] = true;
    
    var plaintext = inputs[op.plaintext],
        printtext;
    if (op.plaintext === "jwk-set+json") {
        printtext = common.prettify(JSON.parse(plaintext));
    } else {
        printtext = common.splitit(plaintext);
    }
    
    var rcpts = op.recipients.map(function(r) {
        if (r.key.kty !== "EC") {
            return Q.resolve();
        }
        
        var crv = r.key.get("crv");
        return jose.JWK.createKeyStore().generate("EC", crv).
               then(function(k) {
                    r.epk = k;
               });
    });
    promise = promise.then(Q.all(rcpts));
    
    promise = promise.then(function() {
        console.log("\n%s Plaintext (utf-8):", op.plaintext);
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log(printtext);
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log("\n%s Plaintext (base64url):", op.plaintext);
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        console.log(common.prettify(jose.base64url.encode(plaintext, "utf8")));
        console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    });
    if (op.opts.zip) {
        promise = promise.then(function() {
            return Q.nfcall(zlib.deflate, new Buffer(plaintext, "utf8"));
        }).then(function(deflated) {
            deflated = jose.base64url.encode(deflated);
            console.log("\n%s Compressed Plaintext (base64url):", op.plaintext);
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            console.log(common.prettify(deflated));
            console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        });
    }
    promise = promise.then(function() {
        console.log("==============================================================");
    });

    return true;
});
promise = promise.then(function() {
    console.log("\n\n");
});

exec.reduce(function(chain, opkey) {
    return chain.then(function() {
        return doOp(ops[opkey]);
    });
}, promise);
