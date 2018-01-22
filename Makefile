.PHONY: test coverage isort check-all check-isort check-flake8

SOURCES = openid setup.py admin contrib

test:
	PYTHONPATH="examples" DJANGO_SETTINGS_MODULE="djopenid.settings" python -m unittest discover

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
