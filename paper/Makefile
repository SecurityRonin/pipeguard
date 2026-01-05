# PipeGuard Academic Paper Build System
# Requires: Quarto, LaTeX (with USENIX packages)

.PHONY: all pdf html clean watch preview

# Default target
all: pdf

# Build PDF using Quarto with arXiv format
pdf:
	quarto render index.qmd --to pdf

# Build HTML for quick preview
html:
	quarto render index.qmd --to html

# Clean build artifacts
clean:
	rm -rf _output/
	rm -f index.tex
	rm -f *.aux *.bbl *.blg *.log *.out *.toc

# Watch for changes and rebuild
watch:
	quarto preview index.qmd

# Preview in browser
preview: html
	open _output/index.html

# Word count (approximate)
wordcount:
	@echo "Approximate word count:"
	@cat sections/*.qmd | wc -w

# Check for common issues
lint:
	@echo "Checking for TODO markers..."
	@grep -rn "TODO\|FIXME\|XXX" sections/ || echo "None found"
	@echo ""
	@echo "Checking for missing citations..."
	@grep -oh '@[a-zA-Z0-9_]*' sections/*.qmd | sort -u | while read cite; do \
		grep -q "$${cite#@}" refs.bib || echo "Missing: $$cite"; \
	done

# Generate standalone LaTeX (for conference submission)
latex: pdf
	@echo "LaTeX file generated at index.tex"

# Help
help:
	@echo "PipeGuard Paper Build System"
	@echo ""
	@echo "Targets:"
	@echo "  pdf       - Build PDF with USENIX format (default)"
	@echo "  html      - Build HTML for quick preview"
	@echo "  clean     - Remove build artifacts"
	@echo "  watch     - Watch for changes and rebuild"
	@echo "  preview   - Build HTML and open in browser"
	@echo "  wordcount - Count words in paper"
	@echo "  lint      - Check for TODOs and missing citations"
	@echo "  latex     - Generate standalone LaTeX"
	@echo "  help      - Show this help"
