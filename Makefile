.PHONY: test coverage

test:
	python admin/runtests

coverage:
	python-coverage erase
	-rm -r htmlcov
	python-coverage run --branch --source="." admin/runtests
	python-coverage html --directory=htmlcov
