.PHONY: test coverage isort check-all check-isort check-flake8

test:
	# TODO: Ignore djopenid tests for the time being
	python -m unittest discover --start openid/test -t .

coverage:
	python -m coverage erase
	-rm -r htmlcov
	# TODO: Ignore djopenid tests for the time being
	python -m coverage run --branch --source="." openid/test/__init__.py discover --start openid/test -t .
	python -m coverage html --directory=htmlcov

isort:
	isort --recursive .

check-all: check-isort check-flake8

check-isort:
	isort --check-only --diff --recursive .

check-flake8:
	flake8 --format=pylint .
