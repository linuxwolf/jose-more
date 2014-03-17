/*!
 * cook-nested - Generats nested example
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

var tmpKeys = [
    JSON.parse(fs.readFileSync(__dirname + "/../pki/signatures.json", "utf8")).keys,
    JSON.parse(fs.readFileSync(__dirname + "/../pki/encryption.json", "utf8")).keys,
    JSON.parse(fs.readFileSync(__dirname + "/../pki/shared.json", "utf8")).keys,
    JSON.parse(fs.readFileSync(__dirname + "/../pki/hobbiton.json", "utf8")).keys
];

var keys = jose.JWK.createKeyStore();
tmpKeys.forEach(function(ks) {
    ks.forEach(function(k) {
        keys.add(k);
    });
});
delete tmpKeys;

var input = {
    "iss":"hobbiton.example",
    "exp":1300819380,
    "http://example.com/is_root":true
};

var ops = {
    "sig": {
        opts: {
            compact: false
        },
        signers: [
            {
                key: keys.get({kid:"hobbiton.example"}),
                header: {
                    alg:"PS256",
                    typ: "JWT"
                },
                reference: null,
                protect: "*"
            }
        ]
    },
    "enc": {
        opts: {
            compact: false,
            zip: false,
            contentAlg: "A128GCM",
            protect: "*",
            fields: {
                cty: "JWT"
            }
        },
        recipients: [
            {
                key: keys.get({kid:"samwise.gamgee@hobbiton.example"}),
                reference: null,
                header: {
                    alg: "RSA-OAEP"
                }
            }
        ]
    }
}

Q.resolve(input).
then(function(input) {
    var utf8, b64u;
    utf8 = common.prettify(input);
    console.log("\nPayload (utf-8):");
    console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    console.log(utf8);
    console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    b64u = JSON.stringify(input);
    b64u = jose.base64url.encode(b64u, "utf8");
    console.log("\nPayload (base64url):");
    console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    console.log(common.prettify(b64u));
    console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    
    console.log("==============================================================");
    
    return JSON.stringify(input); 
}).then(function(payload) {
    var op = ops["sig"];
    var sig = jose.JWS.createSign(op.opts, op.signers);
    sig.update(payload, "utf8");
    
    var promise = sig.final();
    promise = promise.then(function(jws) {
        var compact, json;
        compact = common.makeCompactJWS(jws);
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
        
        compact = compact.replace(/\s+/g, "");
        return compact;
    });
    
    return promise;
}).then(function(plaintext) {
    var printout = plaintext.split(".").
                             map(common.chunk).
                             map(function(v) {
                                if (!v) {
                                    return "\n";
                                } else {
                                    return "\n" + v + "\n"
                                }
                             }).
                             join(".").
                             trim();
    console.log("\nPlaintext:");
    console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    console.log(printout);
    console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    var op = ops["enc"];
    var enc = jose.JWE.createEncrypt(op.opts, op.recipients);
    enc.update(plaintext, "utf8");
    
    var promise = enc.final();
    promise = promise.then(function(jwe) {
        var compact = [], json;
        compact = common.makeCompactJWE(jwe);
        json = common.prettify(jwe);
    
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
            
            if (rprops.epk) {
                // log it separate
                log.push(util.format("\nRecipient #%d Ephemeral Public Key (JSON):", idx+1));
                log.push(util.format("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
                log.push(util.format(common.prettify(rprops.epk)));
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

    return promise;
}).fail(function(err) {
    console.log("failed: " + err.message);
});
