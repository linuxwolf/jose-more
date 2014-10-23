KRAMDOWN=kramdown-rfc2629
RFC2TXT=xml2rfc --text
RFC2HTML=xml2rfc --html
# RFC2HTML=xsltproc --param xml2rfc-toc "'yes'" rfc2629.xslt

SOURCES=draft-ietf-jose-cookbook.mkd
OBJS=$(SOURCES:.mkd=.xml)
TXT_OUTPUT=$(OBJS:.xml=.txt)
HTML_OUTPUT=$(OBJS:.xml=.html)
OUTPUT=$(TXT_OUTPUT) \
		$(HTML_OUTPUT)

.PRECIOUS: %.xml

all :	$(OUTPUT)

txt : $(TXT_OUTPUT)

html : $(HTML_OUTPUT)

xml : $(OBJS)

%.html : %.xml
	$(RFC2HTML) $<

%.txt : %.xml
	$(RFC2TXT) $<

%.xml : %.mkd
	$(KRAMDOWN) $< > $@

clean :
	rm -rf $(OUTPUT) $(OBJS)


.PHONY : all xml txt html clean
