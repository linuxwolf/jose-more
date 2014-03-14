/*!
 * common.js - Common utilities for the example generators
 *
 * This content is in the public domain.
 */
 
var jose = require("jose");

const LINE_LEN = 62,
      BLANK_LINE = "                                                              ";

var chunk = exports.chunk = function(str) {
    var segments = Math.ceil(str.length / BLANK_LINE.length);
    var results = [],
        seglen,
        idx;

    var indent = /^\s*(?=[^\s])/.exec(str),
        line,
        first;
    
    if (!indent) {
        indent = "";
    } else {
        indent = indent[0];
    }
    str = str.substring(indent.length);
    first = true;
    while (str) {
        if ((str.length + indent.length) < BLANK_LINE.length) {
            line = indent + str;
            str = "";
        } else {
            seglen = BLANK_LINE.length - indent.length;
            line = "" + indent + str.substring(0, seglen);
            str = str.substring(seglen);
        }
        results.push(line);
        
        if (first && indent) {
            indent = indent + "    ";
            first = false;
        }
    }
    
    return results.join("\n");
}
var splitit = exports.splitit = function(str) {
    var results = [],
        line,
        pos;
    
    // convert to UTF-8
    str = jose.utf8.encode(str).
          replace(/[\u0080-\u00ff]/g, function(m) {
            return ("\\x" + m.charCodeAt(0).toString(16));
          });
    
    while (str.length) {
        if (str.length < LINE_LEN) {
            pos = -1;
        } else {
            pos = str.lastIndexOf(" ", LINE_LEN);
        }
        
        if (pos === -1) {
            line = str;
            str = "";
        } else {
            line = str.substring(0, pos);
            str = str.substring(pos+1);
        }
        results.push(line);
    }
    
    return results.join("\n");
}

var prettify = exports.prettify = function(input) {
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

var makeCompactJWE = exports.makeCompactJWE = function(json) {
    var jwe = [];
    
    if (typeof(json) === "string") {
        jwe = json.split(".");
    } else {
        if (!json.ciphertext) {
            return [];
        }
        if (json.aad) {
            return [];
        }
        if (json.unprotected) {
            return [];
        }
    
        jwe[0] = json.protected || "";
        jwe[1] = (json.recipients && json.recipients[0] && json.recipients[0].encrypted_key) || "";
        jwe[2] = json.iv || "";
        jwe[3] = json.ciphertext || "";
        jwe[4] = json.tag || "";
    }
    
    return jwe;
}

var makeCompactJWS = exports.makeCompactJWS = function(json) {
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
