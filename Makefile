instructions = glab1.pdf glab2.pdf faq.pdf
programs = parser hub switch vswitch arp router
CFLAGS = -O0 -g # -Wall

all: network-driver $(instructions) $(programs)

network-driver: network-driver.c glab.h
	gcc -g -O0 -Wall -o network-driver network-driver.c

# Try to build instructions, but do not fail hard if this fails:
# the CI doesn't have pdflatex...
$(instructions): %.pdf: %.tex
	pdflatex $<  || true
	pdflatex $<  || true
	pdflatex $<  || true

clean:
	rm -f network-driver sample-parser $(instructions) *.log *.aux *.out $(programs)

$(programs): %: %.c glab.h loop.c print.c
	gcc $(CFLAGS) $< -o $@
