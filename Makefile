.PHONY: install run clean uninstall

install:
	@bash install.sh

run:
	@bash run.sh

clean:
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	@find . -name "*.pyc" -delete 2>/dev/null; true

uninstall:
	@bash uninstall.sh
