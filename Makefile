.PHONY: test test-openid test-djopenid coverage isort check-all check-isort check-flake8

SOURCES = openid setup.py admin contrib

# Run tests by default
all: test

test-openid:
	python -m unittest discover --start=openid

# Run tests for djopenid example
test-djopenid:
	DJANGO_SETTINGS_MODULE="djopenid.settings" python -m unittest discover --start=examples

test: test-openid test-djopenid

coverage:
	python -m coverage erase
	-rm -r htmlcov
	PYTHONPATH="examples" DJANGO_SETTINGS_MODULE="djopenid.settings" python -m coverage run --branch --source="." openid/test/__init__.py discover
	python -m coverage html --directory=htmlcov

isort:
	isort --recursive ${SOURCES}

check-all: check-isort check-flake8

check-isort:
	isort --check-only --diff --recursive ${SOURCES}

check-flake8:
	flake8 --format=pylint ${SOURCES}
