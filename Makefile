.PHONY: test coverage isort check-all check-isort check-flake8

test:
	python admin/runtests

coverage:
	python-coverage erase
	-rm -r htmlcov
	python-coverage run --branch --source="." admin/runtests
	python-coverage html --directory=htmlcov

isort:
	isort --recursive .

check-all: check-isort check-flake8

check-isort:
	isort --check-only --diff --recursive .

check-flake8:
	flake8 --format=pylint .
