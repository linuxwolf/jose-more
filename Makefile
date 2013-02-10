RFC2TXT=xml2rfc --text
RFC2HTML=xml2rfc --html
SOURCES=draft-miller-jose-jwe-protected-jwk.xml \
		draft-miller-jose-pkix-key.xml
TXT_OUTPUT=$(SOURCES:.xml=.txt)
HTML_OUTPUT=$(SOURCES:.xml=.html)
OUTPUT=$(TXT_OUTPUT) \
		$(HTML_OUTPUT)

all :	$(OUTPUT)

txtdocs : $(TXT_OUTPUT)

htmldocs : $(HTML_OUTPUT)

clean :
	rm -rf $(OUTPUT)

%.html : %.xml
	$(RFC2HTML) $<

%.txt : %.xml
	$(RFC2TXT) $<

.PHONY : all txtdocs htmldocs
