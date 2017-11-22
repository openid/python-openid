.PHONY: test coverage isort check-isort

test:
	python admin/runtests

coverage:
	python-coverage erase
	-rm -r htmlcov
	python-coverage run --branch --source="." admin/runtests
	python-coverage html --directory=htmlcov

isort:
	isort --recursive .

check-isort:
	isort --check-only --diff --recursive .
