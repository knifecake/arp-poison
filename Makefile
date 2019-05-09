paper.pdf: paper.md
	pp $^ | pandoc -o $@ --pdf-engine=xelatex --bibliography docs/references.bib --csl docs/ieee.csl

memoria.pdf: docs/*.md docs/references.bib
	pp docs/memoria.md | pandoc -o $@ --pdf-engine=xelatex --bibliography docs/references.bib

memoria.tex: docs/*.md docs/references.bib
	pp docs/memoria.md | pandoc -o $@ --standalone --toc --bibliography docs/references.bib
