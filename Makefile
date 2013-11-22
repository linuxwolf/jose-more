KRAMDOWN=kramdown-rfc2629
RFC2TXT=xml2rfc --text
RFC2HTML=xsltproc rfc2629.xslt

SOURCES=draft-miller-jose-cookbook.mkd
OBJS=$(SOURCES:.mkd=.xml)
TXT_OUTPUT=$(OBJS:.xml=.txt)
HTML_OUTPUT=$(OBJS:.xml=.html)
OUTPUT=$(TXT_OUTPUT) \
		$(HTML_OUTPUT)

.PRECIOUS: %.xml

all :	$(OUTPUT)

txtdocs : $(TXT_OUTPUT)

htmldocs : $(HTML_OUTPUT)

xmldocs : $(OBJS)

%.html : %.xml
	$(RFC2HTML) $< > $@

%.txt : %.xml
	$(RFC2TXT) $<

%.xml : %.mkd
	$(KRAMDOWN) $< > $@

clean :
	rm -rf $(OUTPUT) $(OBJS)


.PHONY : all txtdocs htmldocs clean
