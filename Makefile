.PHONY: buildall clean install

buildall:
	$(MAKE) -C udf2
	$(MAKE) -C udf2_iconv
	$(MAKE) -C mount_udf2

clean:
	$(MAKE) -C udf2 clean
	$(MAKE) -C udf2_iconv clean
	$(MAKE) -C mount_udf2 clean

install:
	$(MAKE) -C udf2 install
	$(MAKE) -C udf2_iconv install
	$(MAKE) -C mount_udf2 install
