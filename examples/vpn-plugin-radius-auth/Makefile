release: vpn-plugin-radius-auth
	cd ../../; make
	cp ../../openvpn-plugin-auth-script.so linux-x86_64-openvpn-plugin-auth-script.so
	sha512sum $< linux-x86_64-openvpn-plugin-auth-script.so >sha512sums.txt

publish: release
	@echo tag me and upload to github

vpn-plugin-radius-auth: vpn_plugin_radius_auth.py
	sed '1s/env //' $< >$@
	chmod 755 $@

clean:
	rm vpn-plugin-radius-auth *.log

clean-all: clean
	rm -r __pycache__/ 

venv:
	python3 -m venv $@

.PHONY: release clean clean-all
