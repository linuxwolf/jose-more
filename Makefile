KRAMDOWN=kramdown-rfc2629
RFC2TXT=xml2rfc --text
RFC2HTML=xml2rfc --html

SOURCES=draft-miller-jose-cookbook.mkd
XML_OUTPUT=$(SOURCES:.mkd=.xml)
TXT_OUTPUT=$(XML_OUTPUT:.xml=.txt)
HTML_OUTPUT=$(XML_OUTPUT:.xml=.html)
OUTPUT=$(TXT_OUTPUT) \
		$(HTML_OUTPUT)

all :	$(OUTPUT)

txtdocs : $(TXT_OUTPUT)

htmldocs : $(HTML_OUTPUT)

clean :
	rm -rf $(OUTPUT) $(XML_OUTPUT)

%.xml : %.mkd
	$(KRAMDOWN) $< > $@

%.html : %.xml
	$(RFC2HTML) $<

%.txt : %.xml
	$(RFC2TXT) $<

.PHONY : all txtdocs htmldocs
