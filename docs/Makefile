msp430static.pdf: msp430static.dvi
	dvipdf msp430static.dvi
msp430static.dvi: msp430static.tex
	latex msp430static.tex
	makeindex msp430static.idx
	latex msp430static.tex


clean:
	rm -f *.dvi
