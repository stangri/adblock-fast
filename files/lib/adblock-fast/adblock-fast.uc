'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2023-2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
//
// Main ucode module for adblock-fast.
// All business logic lives here; the init script is a thin procd wrapper.

import { readfile, writefile, popen, stat, unlink, rename, open, glob, mkdir, mkstemp, symlink, chmod, chown, realpath, lsdir, access, dirname } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';

// ── Constants ───────────────────────────────────────────────────────

const pkg = {
	name: 'adblock-fast',
	version: 'dev-test',
	compat: '12',
	memory_threshold: 33554432,
	config_file: '/etc/config/adblock-fast',
	dnsmasq_file: '/var/run/adblock-fast/adblock-fast.dnsmasq',
	run_file: '/dev/shm/adblock-fast',
	status_file: '/dev/shm/adblock-fast.status.json',
	triggers: {
		reload: 'parallel_downloads debug download_timeout allowed_domain blocked_domain allowed_url blocked_url dns config_update_enabled config_update_url dnsmasq_config_file_url curl_additional_param curl_max_file_size curl_retry',
		restart: 'compressed_cache compressed_cache_dir force_dns led force_dns_port',
	},
};
pkg.service_name = pkg.name + ' ' + pkg.version;

const dns_modes = {
	'dnsmasq.addnhosts': {
		file: '/var/run/' + pkg.name + '/dnsmasq.addnhosts',
		cache: '/var/run/' + pkg.name + '/dnsmasq.addnhosts.cache',
		gzip: pkg.name + '.dnsmasq.addnhosts.gz',
		format_filter: 's|^|127.0.0.1 |;s|$||',
		format_filter_ipv6: 's|^|:: |;s|$||',
		parse_filter: 's|^127.0.0.1 ||;s|^:: ||;',
		grep_pattern_ipv4: 's|^|^127\\.0\\.0\\.1 |',
		grep_pattern_ipv6: 's|^|^:: |',
	},
	'dnsmasq.conf': {
		file: pkg.dnsmasq_file,
		cache: '/var/run/' + pkg.name + '/dnsmasq.conf.cache',
		gzip: pkg.name + '.dnsmasq.conf.gz',
		format_filter: 's|^|local=/|;s|$|/|',
		parse_filter: 's|local=/||;s|/$||;',
		grep_pattern: 's|^|^local=/|;s|$|/$|',
	},
	'dnsmasq.ipset': {
		file: pkg.dnsmasq_file,
		cache: '/var/run/' + pkg.name + '/dnsmasq.ipset.cache',
		gzip: pkg.name + '.dnsmasq.ipset.gz',
		format_filter: 's|^|ipset=/|;s|$|/adb|',
		parse_filter: 's|ipset=/||;s|/adb$||;',
		grep_pattern: 's|^|^ipset=/|;s|$|/adb$|',
	},
	'dnsmasq.nftset': {
		file: pkg.dnsmasq_file,
		cache: '/var/run/' + pkg.name + '/dnsmasq.nftset.cache',
		gzip: pkg.name + '.dnsmasq.nftset.gz',
		format_filter: 's|^|nftset=/|;s|$|/4#inet#fw4#adb4|',
		format_filter_ipv6: 's|^|nftset=/|;s|$|/4#inet#fw4#adb4,6#inet#fw4#adb6|',
		parse_filter: 's|nftset=/||;s|/4#.*$||;',
		grep_pattern: 's|^|^nftset=/|;s|$|/4#.*$|',
	},
	'dnsmasq.servers': {
		file: '/var/run/' + pkg.name + '/dnsmasq.servers',
		cache: '/var/run/' + pkg.name + '/dnsmasq.servers.cache',
		gzip: pkg.name + '.dnsmasq.servers.gz',
		format_filter: 's|^|server=/|;s|$|/|',
		parse_filter: 's|server=/||;s|/.*$||;',
		grep_pattern: 's|^|^server=/|;s|$|/$|',
		allow_filter: 's|(.*)|server=/\\1/#|',
		blocked_count_filter: '\\|/#|d',
	},
	'smartdns.domainset': {
		file: '/var/run/' + pkg.name + '/smartdns.domainset',
		cache: '/var/run/' + pkg.name + '/smartdns.domainset.cache',
		gzip: pkg.name + '.smartdns.domainset.gz',
		config: '/var/run/' + pkg.name + '/smartdns.domainset.conf',
		format_filter: '',
		parse_filter: '',
	},
	'smartdns.ipset': {
		file: '/var/run/' + pkg.name + '/smartdns.ipset',
		cache: '/var/run/' + pkg.name + '/smartdns.ipset.cache',
		gzip: pkg.name + '.smartdns.ipset.gz',
		config: '/var/run/' + pkg.name + '/smartdns.ipset.conf',
		format_filter: '',
		parse_filter: '',
	},
	'smartdns.nftset': {
		file: '/var/run/' + pkg.name + '/smartdns.nftset',
		cache: '/var/run/' + pkg.name + '/smartdns.nftset.cache',
		gzip: pkg.name + '.smartdns.nftset.gz',
		config: '/var/run/' + pkg.name + '/smartdns.nftset.conf',
		format_filter: '',
		parse_filter: '',
	},
	'unbound.adb_list': {
		file: '/var/lib/unbound/adb_list.' + pkg.name,
		cache: '/var/run/' + pkg.name + '/unbound.cache',
		gzip: pkg.name + '.unbound.gz',
		format_filter: 's|^|local-zone: "|;s|$|." always_nxdomain|',
		parse_filter: 's|^local-zone: "||;s|." always_nxdomain$||;',
	},
};

const tmp = {
	allowed: '/var/' + pkg.name + '.allowed.tmp',
	a: '/var/' + pkg.name + '.a.tmp',
	b: '/var/' + pkg.name + '.b.tmp',
	sed: '/var/' + pkg.name + '.sed.tmp',
};

const list_formats = {
	adblockplus: {
		first_line: '[Adblock Plus]',
		detect: "'^||'",
		filter: "/^#/d;/^!/d;s/[[:space:]]*#.*$//;s/^||//;s/\\^$//;s/[[:space:]]*$//;s/[[:cntrl:]]$//;/[[:space:]]/d;/[`~!@#\\$%\\^&\\*()=+;:\"',<>?/\\|[{}]/d;/]/d;/\\./!d;/^$/d;/[^[:alnum:]_.-]/d;",
	},
	dnsmasq: {
		detect: "'^server='",
		filter: "\\|^server=/[[:alnum:]_.-].*/|!d;s|server=/||;s|/.*$||",
	},
	dnsmasq2: {
		detect: "'^local='",
		filter: "\\|^local=/[[:alnum:]_.-].*/|!d;s|local=/||;s|/.*$||",
	},
	dnsmasq3: {
		detect: "'^address='",
		filter: "\\|^address=/[[:alnum:]_.-].*/|!d;s|address=/||;s|/.*$||",
	},
	hosts: {
		detect: "-e '^0\\.0\\.0\\.0\\s' -e '^127\\.0\\.0\\.1\\s'",
		filter: "/localhost/d;/^#/d;/^[^0-9]/d;s/^0\\.0\\.0\\.0.//;s/^127\\.0\\.0\\.1.//;s/[[:space:]]*#.*$//;s/[[:cntrl:]]$//;s/[[:space:]]//g;/[`~!@#\\$%\\^&\\*()=+;:\"',<>?/\\|[{}]/d;/]/d;/\\./!d;/^$/d;/[^[:alnum:]_.-]/d;",
	},
	domains: {
		filter: "/^#/d;s/[[:space:]]*#.*|[[:space:]]*$|[[:cntrl:]]$//g;/^[[:space:]]*$/d;/^-|^\\.|\\.\\.|-$|\\.$|^[0-9.]+$|^[^[:alnum:]]|[`~!@#\\$%\\^&\\*()=+;:\"',<>?/\\|{}]/d;/\\./!d",
	},
};

const sym = {
	dot:  ['.', '[w]'],
	ok:   ['\033[0;32m\xe2\x9c\x93\033[0m', '\033[0;32m[\xe2\x9c\x93]\033[0m'],
	fail: ['\033[0;31m\xe2\x9c\x97\033[0m', '\033[0;31m[\xe2\x9c\x97]\033[0m'],
	warn: ['\033[0;33m\xe2\x9c\x94\033[0m', '\033[0;33m[\xe2\x9c\x94]\033[0m'],
	ERR:  '\033[0;31m[ERROR]\033[0m',
	WARN: '\033[0;33m[WARN]\033[0m',
};

const canary = {
	mozilla: 'use-application-dns.net',
	icloud: 'mask.icloud.com mask-h2.icloud.com',
};

// ── Mutable Module State ────────────────────────────────────────────

let state = {
	script_name: pkg.name,
	dl_command: null,
	dl_flag: null,
	ssl_supported: false,
	environment_loaded: false,
	config_loaded: false,
	fw4_restart: false,
	dnsmasq_features: null,
	dnsmasq_ubus: null,
	awk_cmd: 'awk',
	output_queue: '',
	is_tty: null,
};

let dns_output = {
	allow_filter: null,
	blocked_count_filter: null,
	filter: null,
	filter_ipv6: null,
	file: null,
	gzip: null,
	cache: null,
	config: null,
	parse_filter: null,
};

// Config values loaded by load()
let cfg = {};

// ── Shell / System Helpers ──────────────────────────────────────────

function shell_quote(s) {
	return "'" + replace('' + s, "'", "'\\''") + "'";
}

function cmd_output(c) {
	let p = popen(c, 'r');
	if (!p) return '';
	let data = p.read('all') || '';
	p.close();
	return trim(data);
}

function cmd_rc(c) {
	return system(c + ' >/dev/null 2>&1');
}

function ensure_trailing_newline(file) {
	let fh = open(file, 'r+');
	if (!fh) return;
	if (fh.seek(-1, 2) && fh.read(1) != '\n')
		fh.write('\n');
	fh.close();
}

function mkdir_p(path) {
	if (!path || stat(path)?.type == 'directory') return true;
	let parent = dirname(path);
	if (parent && parent != path) mkdir_p(parent);
	return mkdir(path) != null;
}

function is_present(cmd) {
	if (index(cmd, '/') >= 0)
		return access(cmd, 'x') == true;
	for (let dir in ['/usr/sbin', '/usr/bin', '/sbin', '/bin'])
		if (access(dir + '/' + cmd, 'x') == true) return true;
	return false;
}

function is_integer(v) {
	if (v == null || v == '') return false;
	if (!match('' + v, /^[0-9]+$/)) return false;
	let n = int(v);
	return n >= 1 && n <= 65535;
}

function is_https_url(url) {
	return substr('' + url, 0, 8) == 'https://';
}

function sanitize_domain(d) {
	d = replace('' + d, /^[a-z]+:\/\//, '');
	d = replace(d, /\/.*$/, '');
	d = replace(d, /:.*$/, '');
	return d;
}

function sanitize_dir(d) {
	let r = realpath(d);
	if (r && stat(r)?.type == 'directory') return r;
	return null;
}

function str_contains_word(haystack, needle) {
	if (!haystack || !needle) return false;
	return index(split('' + haystack, /\s+/), needle) >= 0;
}

// ── Shell Command Wrappers ──────────────────────────────────────────

function sed_filter(expr, input, output) {
	return system(sprintf('sed %s %s > %s',
		shell_quote(expr), shell_quote(input), shell_quote(output))) == 0;
}

function sed_inplace(expr, file) {
	return system(sprintf('sed -i %s %s',
		shell_quote(expr), shell_quote(file))) == 0;
}

function sed_script(script, input, output) {
	return system(sprintf('sed -E -f %s %s > %s',
		shell_quote(script), shell_quote(input), shell_quote(output))) == 0;
}

function sort_file(input, output, unique) {
	return system(sprintf('sort %s%s > %s',
		unique ? '-u ' : '', shell_quote(input), shell_quote(output))) == 0;
}

function gzip_test(file) {
	return system(sprintf('gzip -t -c %s >/dev/null 2>/dev/null',
		shell_quote(file))) == 0;
}

function gzip_compress(input, output) {
	return system(sprintf('gzip < %s > %s',
		shell_quote(input), shell_quote(output))) == 0;
}

function gzip_decompress(input, output) {
	return system(sprintf('gzip -dc < %s > %s',
		shell_quote(input), shell_quote(output))) == 0;
}

function grep_test(pattern, file, flags) {
	return cmd_rc(sprintf('grep %s %s %s',
		flags || '-q', shell_quote(pattern), shell_quote(file))) == 0;
}

function grep_count(pattern, file, flags) {
	return int(trim(cmd_output(sprintf('grep %s %s %s',
		flags || '-c', shell_quote(pattern), shell_quote(file)))) || '0');
}

function grep_output(pattern, file, flags) {
	return cmd_output(sprintf('grep %s %s %s',
		flags || '', shell_quote(pattern), shell_quote(file)));
}

function grep_exclude_file(patfile, input, output) {
	return system(sprintf('grep -vFf %s %s > %s 2>/dev/null',
		shell_quote(patfile), shell_quote(input), shell_quote(output))) == 0;
}

function count_lines(file, filter_expr) {
	if (filter_expr)
		return int(trim(cmd_output(sprintf('sed %s %s | wc -l',
			shell_quote(filter_expr), shell_quote(file)))) || '0');
	return int(trim(cmd_output('wc -l < ' + shell_quote(file))) || '0');
}

function awk_reverse_labels(input, output) {
	return system(sprintf("%s -F '.' '{for(i=NF;i>0;i--) printf \"%%s%%s\", $i, (i>1?\".\":\"\\n\")}' %s > %s",
		state.awk_cmd, shell_quote(input), shell_quote(output))) == 0;
}

function awk_dedup_subdomains(input, output) {
	return system(sprintf("%s 'NR==1{prev=$0;print;next}{len=length(prev);if(substr($0,1,len)==prev && substr($0,len+1,1)==\".\") next;print;prev=$0}' %s > %s",
		state.awk_cmd, shell_quote(input), shell_quote(output))) == 0;
}

function download(url, dest) {
	return system(sprintf('%s %s %s %s 2>/dev/null',
		state.dl_command, shell_quote(url), state.dl_flag, shell_quote(dest))) == 0;
}

function service_restart(name) {
	return system(sprintf('/etc/init.d/%s restart >/dev/null 2>&1', name)) == 0;
}

function service_enabled(name) {
	return system(sprintf('/etc/init.d/%s enabled >/dev/null 2>&1', name)) == 0;
}

// ── Memory / System Info ────────────────────────────────────────────

function get_mem_available() {
	let conn = connect();
	if (!conn) return 0;
	let info = conn.call('system', 'info');
	conn.disconnect();
	if (!info) return 0;
	let ram = info?.memory?.available || 0;
	let swap = info?.swap?.free || 0;
	return ram + swap;
}

function get_mem_total() {
	let conn = connect();
	if (!conn) return 0;
	let info = conn.call('system', 'info');
	conn.disconnect();
	if (!info) return 0;
	let ram = info?.memory?.total || 0;
	let swap = info?.swap?.total || 0;
	return ram + swap;
}

function led_on(l) {
	if (l && stat(l + '/trigger'))
		writefile(l + '/trigger', 'default-on\n');
}

function led_off(l) {
	if (l && stat(l + '/trigger'))
		writefile(l + '/trigger', 'none\n');
}

function logger(msg) {
	system('/usr/bin/logger -t ' + shell_quote(state.script_name) + ' ' + shell_quote(msg));
}

function logger_debug(msg) {
	if (cfg.debug_performance)
		system('/usr/bin/logger -t ' + shell_quote(state.script_name) + ' ' + shell_quote(msg));
}

// ── Output Management ───────────────────────────────────────────────

let _write = function(level, ...args) {
	if (!cfg.verbosity)
		cfg.verbosity = int(uci(pkg.name).get(pkg.name, 'config', 'verbosity') || '1');
	let msg = join('', args);
	if (level != null && (cfg.verbosity & level) == 0) return;

	// Print to stderr (terminal)
	if (state.is_tty == null)
		state.is_tty = (system('[ -t 2 ]') == 0);
	if (state.is_tty)
		warn(replace(msg, /\\n/g, '\n'));

	// Queue for logger: flush on newline
	if (index(msg, '\\n') >= 0 || index(msg, '\n') >= 0) {
		msg = state.output_queue + msg;
		state.output_queue = '';
		let clean = replace(msg, /\x1b\[[0-9;]*m/g, '');
		clean = replace(clean, /\\n/g, '\n');
		clean = trim(clean);
		if (clean != '')
			system('/usr/bin/logger -t ' + shell_quote(state.script_name) + ' ' + shell_quote(clean));
	} else {
		state.output_queue += msg;
	}
};

let output = {
	_write:  _write,
	info:    function(...args) { _write(1, ...args); },
	verbose: function(...args) { _write(2, ...args); },
	print:   function(...args) { _write(null, ...args); },
	ok:      function() { _write(1, sym.ok[0]); _write(2, sym.ok[1] + '\\n'); },
	okn:     function() { _write(1, sym.ok[0] + '\\n'); _write(2, sym.ok[1] + '\\n'); },
	fail:    function() { _write(1, sym.fail[0]); _write(2, sym.fail[1] + '\\n'); },
	failn:   function() { _write(1, sym.fail[0] + '\\n'); _write(2, sym.fail[1] + '\\n'); },
	warn:    function() { _write(1, sym.warn[0]); _write(2, sym.warn[1] + '\\n'); },
	warnn:   function() { _write(1, sym.warn[0] + '\\n'); _write(2, sym.warn[1] + '\\n'); },
	dot:     function() { _write(1, sym.dot[0]); _write(2, sym.dot[1]); },
	dns:     function(msg) {
		if (!cfg.dns) return;
		let d = '' + cfg.dns;
		if (index(d, 'dnsmasq.') == 0) _write(2, '[DNSM] ' + msg);
		else if (index(d, 'smartdns.') == 0) _write(2, '[SMRT] ' + msg);
		else if (index(d, 'unbound.') == 0) _write(2, '[UNBD] ' + msg);
	},
	error:   function(msg) { _write(null, sym.ERR + ' ' + msg + '!\\n'); },
	warning: function(msg) { _write(null, sym.WARN + ' ' + msg + '!\\n'); },
};

// ── UCI Cursor ──────────────────────────────────────────────────────

let _cursor = null;
let _cursor_loaded = {};

function uci(config, reload) {
	if (!_cursor) _cursor = cursor();
	if (!_cursor_loaded[config] || reload) {
		_cursor.load(config);
		_cursor_loaded[config] = true;
	}
	return _cursor;
}

function uci_has_changes(config) {
	return length(uci(config).changes(config) || []) > 0;
}

function uci_list_add_if_new(config, section, option, value) {
	if (!config || !section || !option || !value) return false;
	let ctx = uci(config);
	let current = ctx.get(config, section, option);
	if (type(current) == 'array' && index(current, value) >= 0) return true;
	if (current == value) return true;
	ctx.list_append(config, section, option, value);
	ctx.save(config);
	return true;
}

// ── Status Data ─────────────────────────────────────────────────────

let status_data = {
	status: '',
	message: '',
	stats: '',
	errors: [],
	warnings: [],
};

function status_json(action) {
	switch (action) {
	case 'load':
		let content = readfile(pkg.status_file);
		if (!content) return;
		try {
			let obj = json('' + content);
			if (obj?.data) {
				status_data.status = obj.data.status || '';
				status_data.message = obj.data.message || '';
				status_data.stats = obj.data.stats || '';
				status_data.errors = obj.data.errors || [];
				status_data.warnings = obj.data.warnings || [];
			}
		} catch(e) {}
		break;
	case 'dump':
		let dump_obj = {
			data: {
				version: pkg.version,
				packageCompat: pkg.compat,
				status: status_data.status,
				message: status_data.message,
				stats: status_data.stats,
				errors: status_data.errors,
				warnings: status_data.warnings,
			}
		};
		let dir = dirname(pkg.status_file);
		mkdir_p(dir);
		let tmp_path = pkg.status_file + '.tmp';
		writefile(tmp_path, sprintf('%J', dump_obj) + '\n');
		rename(tmp_path, pkg.status_file);
		break;
	case 'reset':
		status_data.status = '';
		status_data.message = '';
		status_data.stats = '';
		status_data.errors = [];
		status_data.warnings = [];
		break;
	}
}

// ── get_text ────────────────────────────────────────────────────────

function get_text(r, ...args) {
	let a = args[0] || '';
	switch (r) {
	case 'errorConfigValidationFail': return sprintf("The %s config validation failed", pkg.name);
	case 'errorServiceDisabled': return sprintf("The %s is currently disabled", pkg.name);
	case 'errorNoDnsmasqIpset': return sprintf("The dnsmasq ipset support is enabled in %s, but dnsmasq is either not installed or installed dnsmasq does not support ipset", pkg.name);
	case 'errorNoIpset': return sprintf("The dnsmasq ipset support is enabled in %s, but ipset is either not installed or installed ipset does not support 'hash:net' type", pkg.name);
	case 'errorNoDnsmasqNftset': return sprintf("The dnsmasq nft set support is enabled in %s, but dnsmasq is either not installed or installed dnsmasq does not support nft set", pkg.name);
	case 'errorNoNft': return sprintf("The dnsmasq nft sets support is enabled in %s, but nft is not installed", pkg.name);
	case 'errorNoWanGateway': return sprintf("The %s failed to discover WAN gateway", pkg.service_name);
	case 'errorOutputDirCreate': return sprintf("Failed to create directory for %s file", a);
	case 'errorOutputFileCreate': return sprintf("Failed to create %s file", a);
	case 'errorFailDNSReload': return "Failed to restart/reload DNS resolver";
	case 'errorSharedMemory': return "Failed to access shared memory";
	case 'errorSorting': return "Failed to sort data file";
	case 'errorOptimization': return "Failed to optimize data file";
	case 'errorAllowListProcessing': return "Failed to process allow-list";
	case 'errorDataFileFormatting': return "Failed to format data file";
	case 'errorCopyingDataFile': return sprintf("Failed to copy data file to '%s'", a);
	case 'errorMovingDataFile': return sprintf("Failed to move data file to '%s'", a);
	case 'errorCreatingCompressedCache': return "Failed to create compressed cache";
	case 'errorRemovingTempFiles': return "Failed to remove temporary files";
	case 'errorRestoreCompressedCache': return "Failed to unpack compressed cache";
	case 'errorRestoreCache': return sprintf("Failed to move '%s' to '%s'", dns_output.cache, dns_output.file);
	case 'errorOhSnap': return "Failed to create block-list or restart DNS resolver";
	case 'errorStopping': return sprintf("Failed to stop %s", pkg.service_name);
	case 'errorDNSReload': return "Failed to reload/restart DNS resolver";
	case 'errorDownloadingConfigUpdate': return "Failed to download Config Update file";
	case 'errorDownloadingList': return sprintf("Failed to download %s", a);
	case 'errorParsingConfigUpdate': return "Failed to parse Config Update file";
	case 'errorParsingList': return "Failed to parse";
	case 'errorNoSSLSupport': return "No HTTPS/SSL support on device";
	case 'errorCreatingDirectory': return "Failed to create output/cache/gzip file directory";
	case 'errorDetectingFileType': return "Failed to detect format";
	case 'errorNothingToDo': return "No blocked list URLs nor blocked-domains enabled";
	case 'errorTooLittleRam': return sprintf("Free ram (%s) is not enough to process all enabled block-lists", a);
	case 'errorCreatingBackupFile': return sprintf("Failed to create backup file %s", a);
	case 'errorDeletingDataFile': return sprintf("Failed to delete data file %s", a);
	case 'errorRestoringBackupFile': return sprintf("Failed to restore backup file %s", a);
	case 'errorNoOutputFile': return sprintf("Failed to create final block-list %s", a);
	case 'errorNoHeartbeat': return "Heartbeat domain is not accessible after resolver restart";
	case 'statusNoInstall': return sprintf("The %s is not installed or not found", pkg.service_name);
	case 'statusStopped': return "stopped";
	case 'statusStarting': return "starting";
	case 'statusRestarting': return "restarting";
	case 'statusForceReloading': return "force-reloading";
	case 'statusDownloading': return "downloading";
	case 'statusProcessing': return "processing";
	case 'statusFail': return "failed to start";
	case 'statusSuccess': return "success";
	case 'statusTriggerBootWait': return "waiting for trigger (on_boot)";
	case 'statusTriggerStartWait': return "waiting for trigger (on_start)";
	case 'warningExternalDnsmasqConfig': return "Use of external dnsmasq config file detected, please set 'dns' option to 'dnsmasq.conf'";
	case 'warningMissingRecommendedPackages': return "Some recommended packages are missing";
	case 'warningInvalidCompressedCacheDir': return sprintf("Invalid compressed cache directory '%s'", a);
	case 'warningFreeRamCheckFail': return "Can't detect free RAM";
	case 'warningSanityCheckTLD': return sprintf("Sanity check discovered TLDs in %s", a);
	case 'warningSanityCheckLeadingDot': return sprintf("Sanity check discovered leading dots in %s", a);
	case 'warningInvalidDomainsRemoved': return sprintf("Removed %s invalid domain entries from block-list (domains starting with -/./numbers or containing invalid patterns)", a);
	default: return sprintf("Unknown error/warning '%s'", a);
	}
}

// ── Resolver Checks ─────────────────────────────────────────────────

function check_dnsmasq() { return is_present('dnsmasq'); }
function check_smartdns() { return is_present('smartdns'); }
function check_unbound() { return is_present('unbound'); }
function check_ipset() { return is_present('ipset') && cmd_rc('/usr/sbin/ipset help hash:net') == 0; }
function check_nft() { return is_present('nft'); }

function check_dnsmasq_feature(feat) {
	if (!state.dnsmasq_features) {
		let raw = cmd_output('dnsmasq --version');
		let m = match(raw, /Compile time options:(.+)/);
		state.dnsmasq_features = (m ? m[1] : '') + ' ';
	}
	switch (feat) {
	case 'idn': return index('' + state.dnsmasq_features, ' IDN ') >= 0;
	case 'ipset': return index('' + state.dnsmasq_features, ' ipset ') >= 0;
	case 'nftset': return index('' + state.dnsmasq_features, ' nftset ') >= 0;
	}
	return false;
}

function check_dnsmasq_ipset() { return check_ipset() && check_dnsmasq_feature('ipset'); }
function check_dnsmasq_nftset() { return check_nft() && check_dnsmasq_feature('nftset'); }

// ── Port/Firewall Helpers ───────────────────────────────────────────

function is_port_listening(port) {
	if (!is_integer(port)) return false;
	let port_hex = sprintf('%04X', int(port));
	for (let path in ['/proc/net/tcp', '/proc/net/tcp6']) {
		let lines = split(readfile(path) || '', '\n');
		for (let i = 1; i < length(lines); i++) {
			let fields = split(trim(lines[i]), /\s+/);
			if (length(fields) < 4) continue;
			if (uc(split(fields[1], ':')[1]) == port_hex && fields[3] == '0A')
				return true;
		}
	}
	for (let path in ['/proc/net/udp', '/proc/net/udp6']) {
		let lines = split(readfile(path) || '', '\n');
		for (let i = 1; i < length(lines); i++) {
			let fields = split(trim(lines[i]), /\s+/);
			if (length(fields) < 2) continue;
			if (uc(split(fields[1], ':')[1]) == port_hex)
				return true;
		}
	}
	return false;
}

function is_fw4_restart_needed() {
	if (state.fw4_restart) return true;
	let d = (uci(pkg.name).get(pkg.name, 'config', 'dns') ?? 'dnsmasq.servers');
	let fd = (uci(pkg.name).get(pkg.name, 'config', 'force_dns') ?? '1');
	if (fd == '1') return true;
	if (d == 'dnsmasq.ipset' || d == 'dnsmasq.nftset' ||
		d == 'smartdns.ipset' || d == 'smartdns.nftset') return true;
	return false;
}

// ── File Size Helpers ───────────────────────────────────────────────

function get_local_filesize(file) {
	let s = stat(file);
	return s ? s.size : null;
}

function get_url_filesize(url) { // ucode-lsp disable
	if (!url) return null;
	let size = '';
	if (is_present('curl')) {
		size = cmd_output(sprintf("curl --silent --insecure --fail --head --request GET --connect-timeout 2 %s | awk -F': ' '{IGNORECASE=1}/content-length/ {gsub(/\\r/, \"\"); print $2}'", shell_quote(url)));
	}
	if (!size && is_present('uclient-fetch')) {
		size = cmd_output(sprintf("uclient-fetch --spider --timeout 2 %s -O /dev/null 2>&1 | sed -n '/^Download/ s/.*\\(\\([0-9]*\\) bytes\\).*/\\1/p'", shell_quote(url)));
	}
	return size ? size : null;
}

// ── count_blocked_domains ───────────────────────────────────────────

function count_blocked_domains() {
	if (!dns_output.file || !stat(dns_output.file)) return '0';
	if (dns_output.blocked_count_filter)
		return '' + count_lines(dns_output.file, dns_output.blocked_count_filter);
	return '' + count_lines(dns_output.file);
}

// ── DNS Output Values ───────────────────────────────────────────────

function dns_set_output_values(d) {
	let dc = dns_modes[d];
	if (!dc) return;
	dns_output.file = dc.file;
	dns_output.cache = dc.cache;
	dns_output.gzip = cfg.compressed_cache_dir + '/' + dc.gzip;
	dns_output.parse_filter = dc.parse_filter;
	dns_output.config = dc.config || null;
	dns_output.allow_filter = dc.allow_filter || null;
	dns_output.blocked_count_filter = dc.blocked_count_filter || null;
	dns_output.filter_ipv6 = null;
	if (d == 'dnsmasq.nftset' && cfg.ipv6_enabled && dc.format_filter_ipv6)
		dns_output.filter = dc.format_filter_ipv6;
	else
		dns_output.filter = dc.format_filter;
	if (d == 'dnsmasq.addnhosts' && cfg.ipv6_enabled && dc.format_filter_ipv6)
		dns_output.filter_ipv6 = dc.format_filter_ipv6;
}

// ── adb_file ────────────────────────────────────────────────────────

function adb_file(action) {
	switch (action) {
	case 'create':
	case 'backup':
		if (stat(dns_output.file)?.size > 0)
			return rename(dns_output.file, dns_output.cache) == true;
		return false;
	case 'restore':
	case 'use':
		if (stat(dns_output.cache)?.size > 0)
			return rename(dns_output.cache, dns_output.file) == true;
		return false;
	case 'test':
	case 'test_file':
		return (stat(dns_output.file)?.size > 0);
	case 'test_cache':
		return (stat(dns_output.cache)?.size > 0);
	case 'test_gzip':
		return (stat(dns_output.gzip)?.size > 0) && gzip_test(dns_output.gzip);
	case 'create_gzip':
		if (!(stat(dns_output.file)?.size > 0)) return false;
		unlink(dns_output.gzip);
		// Write temp file in same directory as destination to avoid cross-filesystem rename
		let gz_tmp = dns_output.gzip + '.tmp';
		if (gzip_compress(dns_output.file, gz_tmp)) {
			if (rename(gz_tmp, dns_output.gzip)) {
				return true;
			}
			unlink(gz_tmp);
		}
		return false;
	case 'expand':
	case 'unpack':
	case 'unpack_gzip':
		if (stat(dns_output.gzip)?.size > 0)
			return gzip_decompress(dns_output.gzip, dns_output.cache);
		return false;
	case 'remove_cache':
		unlink(dns_output.cache);
		return true;
	case 'remove_gzip':
		unlink(dns_output.gzip);
		return true;
	}
	return false;
}

// ── Declarative Config Schema ───────────────────────────────────────
// Each entry: [type, default] — mirrors the shell load_validate_config() spec.

const config_schema = {
	// Booleans
	allow_non_ascii:         ['bool', false],
	canary_domains_icloud:   ['bool', false],
	canary_domains_mozilla:  ['bool', false],
	compressed_cache:        ['bool', false],
	config_update_enabled:   ['bool', false],
	debug_init_script:       ['bool', false],
	debug_performance:       ['bool', false],
	dnsmasq_sanity_check:    ['bool', true],
	dnsmasq_validity_check:  ['bool', false],
	enabled:                 ['bool', false],
	force_dns:               ['bool', true],
	ipv6_enabled:            ['bool', false],
	parallel_downloads:      ['bool', true],
	procd_trigger_wan6:      ['bool', false],
	update_config_sizes:     ['bool', true],
	// Strings
	config_update_url:       ['string', 'https://cdn.jsdelivr.net/gh/openwrt/packages/net/adblock-fast/files/adblock-fast.config.update'],
	curl_additional_param:   ['string'],
	curl_max_file_size:      ['string'],
	curl_retry:              ['string', '3'],
	dns:                     ['string', 'dnsmasq.servers'],
	dnsmasq_config_file_url: ['string'],
	download_timeout:        ['string', '20'],
	heartbeat_sleep_timeout: ['string', '10'],
	led:                     ['string'],
	pause_timeout:           ['string', '20'],
	procd_boot_wan_timeout:  ['string', '60'],
	// Integers
	verbosity:               ['int', 2],
	// Lists
	allowed_domain:          ['list'],
	blocked_domain:          ['list'],
	dnsmasq_instance:        ['list', '*'],
	force_dns_interface:     ['list', 'lan'],
	force_dns_port:          ['list', '53 853'],
	smartdns_instance:       ['list', '*'],
	// Domain (sanitized, '-' means disabled)
	heartbeat_domain:        ['domain', 'heartbeat.melmac.ca'],
	// Directory (validated via realpath)
	compressed_cache_dir:    ['dir', '/etc'],
};

// ── parse_options ───────────────────────────────────────────────────

function parse_options(raw, schema) {
	let result = {};
	for (let key in schema) {
		let spec = schema[key];
		let v = raw[key];
		switch (spec[0]) {
		case 'bool':
			result[key] = (v == null) ? spec[1] : (v == '1' || v == 'yes' || v == 'on' || v == 'true');
			break;
		case 'string':
			result[key] = (v == null) ? (spec[1] ?? null) : '' + v;
			break;
		case 'int':
			result[key] = (v == null) ? (spec[1] ?? 0) : int(v);
			break;
		case 'list':
			if (v == null) { result[key] = spec[1] ?? null; }
			else { result[key] = replace((type(v) == 'array') ? join(' ', v) : '' + v, /,/g, ' '); }
			break;
		case 'domain':
			if (v == null || v == '-') result[key] = spec[1] ?? null;
			else result[key] = sanitize_domain('' + v) || spec[1] || null;
			break;
		case 'dir':
			let d = sanitize_dir('' + (v ?? spec[1] ?? ''));
			result[key] = (d == '/') ? '' : (d || spec[1] || '');
			break;
		}
	}
	return result;
}

// ── load (config) ───────────────────────────────────────────────────

function load() {
	if (state.config_loaded) return;
	let raw = uci(pkg.name, true).get_all(pkg.name, 'config') || {};
	cfg = parse_options(raw, config_schema);
	dns_set_output_values(cfg.dns);
	state.environment_loaded = false;
	state.config_loaded = true;
}

// ── load_dl_command ─────────────────────────────────────────────────

function load_dl_command() {
	if (is_present('curl')) {
		state.dl_command = 'curl -f --silent --insecure';
		if (cfg.curl_additional_param) state.dl_command += ' ' + cfg.curl_additional_param;
		if (cfg.curl_max_file_size) state.dl_command += ' --max-filesize ' + cfg.curl_max_file_size;
		if (cfg.curl_retry) state.dl_command += ' --retry ' + cfg.curl_retry;
		if (cfg.download_timeout) state.dl_command += ' --connect-timeout ' + cfg.download_timeout;
		state.dl_flag = '-o';
	} else if (is_present('/usr/libexec/wget-ssl')) {
		state.dl_command = '/usr/libexec/wget-ssl --no-check-certificate -q';
		if (cfg.download_timeout) state.dl_command += ' --timeout ' + cfg.download_timeout;
		state.dl_flag = '-O';
	} else if (is_present('wget') && cmd_rc("wget --version 2>/dev/null | grep -q '+https'") == 0) {
		state.dl_command = 'wget --no-check-certificate -q';
		if (cfg.download_timeout) state.dl_command += ' --timeout ' + cfg.download_timeout;
		state.dl_flag = '-O';
	} else {
		state.dl_command = 'uclient-fetch --no-check-certificate -q';
		if (cfg.download_timeout) state.dl_command += ' --timeout ' + cfg.download_timeout;
		state.dl_flag = '-O';
	}

	if (cmd_rc("curl --version 2>/dev/null | grep -q 'Protocols: .*https.*'") == 0 ||
		cmd_rc("wget --version 2>/dev/null | grep -q '+ssl'") == 0)
		state.ssl_supported = true;
	else
		state.ssl_supported = false;
}

// ── load_network ────────────────────────────────────────────────────

function load_network(param) {
	let wan_if = null;
	let wan_gw = null;
	let wan_if_timeout = int(cfg.procd_boot_wan_timeout || 60);
	let wan_gw_timeout = 5;

	let counter = 0;
	while (!wan_if) {
		let ub = connect();
		if (ub) {
			let dump = ub.call('network.interface', 'dump');
			if (dump?.interface) {
				for (let iface in dump.interface) {
					for (let r in (iface.route || []))
						if (r.target == '0.0.0.0') { wan_if = iface.interface; break; }
					if (wan_if) break;
				}
			}
			ub.disconnect();
		}
		if (wan_if) {
			output.info("WAN interface found: '" + wan_if + "'.\\n");
			output.verbose("[BOOT] WAN interface found: '" + wan_if + "'.\\n");
			break;
		}
		if (counter > wan_if_timeout) {
			output.info("WAN interface timeout, assuming 'wan'.\\n");
			output.verbose("[BOOT] WAN interface timeout, assuming 'wan'.\\n");
			wan_if = 'wan';
			break;
		}
		counter++;
		output.info("Waiting to discover WAN Interface...\\n");
		output.verbose("[BOOT] Waiting to discover WAN Interface...\\n");
		system('sleep 1');
	}

	// Check if PPPoE → extend gateway timeout
	let proto = uci('network').get('network', wan_if, 'proto');
	if (proto == 'pppoe') wan_gw_timeout += 10;

	counter = 0;
	while (counter <= wan_gw_timeout) {
		let ub = connect();
		if (ub) {
			let status = ub.call('network.interface.' + wan_if, 'status');
			for (let r in (status?.route || []))
				if (r.target == '0.0.0.0') { wan_gw = r.nexthop; break; }
			ub.disconnect();
		}
		if (wan_gw) {
			output.info("WAN gateway found: '" + wan_gw + ".'\\n");
			output.verbose("[BOOT] WAN gateway found: '" + wan_gw + ".'\\n");
			return true;
		}
		counter++;
		output.info("Waiting to discover " + wan_if + " gateway...\\n");
		output.verbose("[BOOT] Waiting to discover " + wan_if + " gateway...\\n");
		system('sleep 1');
	}
	push(status_data.errors, { code: 'errorNoWanGateway', info: '' });
	output.error(get_text('errorNoWanGateway'));
	return false;
}

// ── detect_file_type ────────────────────────────────────────────────

function detect_file_type(file) {
	let first_line = split(readfile(file) || '', '\n')[0];
	for (let name in keys(list_formats)) {
		let fmt = list_formats[name];
		if (fmt.first_line && first_line == fmt.first_line) return name;
		if (fmt.detect && cmd_rc("grep -q " + fmt.detect + " " + shell_quote(file)) == 0) return name;
	}
	if (list_formats.domains) {
		let test = cmd_output(sprintf("sed %s %s 2>/dev/null | head -1", shell_quote(list_formats.domains.filter), shell_quote(file)));
		if (test) return 'domains';
	}
	return null;
}

// ── adb_config_cache ────────────────────────────────────────────────

function adb_config_cache(action, variable) {
	switch (action) {
	case 'create':
	case 'set':
		writefile(pkg.run_file, readfile(pkg.config_file) || '');
		return;
	case 'get':
		switch (variable) {
		case 'trigger_fw4':
			if (stat(pkg.run_file)?.size > 0) {
				if (is_fw4_restart_needed()) return 'true';
			}
			return '';
		case 'trigger_service':
			if (!(stat(pkg.run_file)?.size > 0)) return 'on_boot';
			if ((readfile(pkg.config_file) || '') != (readfile(pkg.run_file) || '')) {
				// Config changed — determine if reload or restart
				let run_dir = dirname(pkg.run_file);
				let cached = cursor(run_dir);
				cached.load(pkg.name);
				let reload_triggers = split(pkg.triggers.reload, ' ');
				for (let t in reload_triggers) {
					if (!t) continue;
					if (t == 'allowed_url' || t == 'blocked_url') continue;
					let val_current = uci(pkg.name).get(pkg.name, 'config', t);
					let val_old = cached.get(pkg.name, 'config', t);
					if ('' + (val_current ?? '') != '' + (val_old ?? '')) return 'download';
				}
				let restart_triggers = split(pkg.triggers.restart, ' ');
				for (let t in restart_triggers) {
					if (!t) continue;
					let val_current = uci(pkg.name).get(pkg.name, 'config', t);
					let val_old = cached.get(pkg.name, 'config', t);
					if ('' + (val_current ?? '') != '' + (val_old ?? '')) return 'restart';
				}
			}
			return '';
		default: {
			let run_dir = dirname(pkg.run_file);
			let old_cfg = cursor(run_dir);
			old_cfg.load(pkg.name);
			return old_cfg.get(pkg.name, 'config', variable) ?? '';
		}
		}
	}
}

// ── append_url (collect file_url sections) ──────────────────────────

function append_urls() {
	cfg.allowed_url = '';
	cfg.blocked_url = '';
	uci(pkg.name).foreach(pkg.name, 'file_url', (s) => {
		if (s.enabled == '0') return;
		let url = s.url;
		if (!url) return;
		if ((s.action || 'block') == 'allow')
			cfg.allowed_url = (cfg.allowed_url ? cfg.allowed_url + ' ' : '') + url;
		else
			cfg.blocked_url = (cfg.blocked_url ? cfg.blocked_url + ' ' : '') + url;
	});
}

// ── load_environment ────────────────────────────────────────────────

function load_environment(param, validation_result) {
	if (state.environment_loaded) return true;
	load();

	if (!cfg.enabled) {
		push(status_data.errors, { code: 'errorServiceDisabled', info: '' });
		output.error(get_text('errorServiceDisabled'));
		output.print("Run the following commands before starting service again:\\n");
		output.print("uci set " + pkg.name + ".config.enabled='1'; uci commit " + pkg.name + ";\\n");
		return false;
	}

	if (validation_result && validation_result != '0') {
		output.info(sym.fail[0] + '\\n');
		push(status_data.errors, { code: 'errorConfigValidationFail', info: '' });
		output.error(get_text('errorConfigValidationFail'));
		output.print("Please check if the '" + pkg.config_file + "' contains correct values for config options.\\n");
		return false;
	}

	// Check resolver presence
	let dns_family = split(cfg.dns, '.')[0];
	switch (dns_family) {
	case 'dnsmasq':
		if (!check_dnsmasq()) {
			if (param != 'quiet') {
				push(status_data.errors, { code: 'errorDNSReload', info: '' });
				output.error("Resolver 'dnsmasq' not found");
			}
			return false;
		}
		if (check_dnsmasq_feature('idn')) cfg.allow_non_ascii = false;
		break;
	case 'smartdns':
		if (!check_smartdns()) {
			if (param != 'quiet') {
				push(status_data.errors, { code: 'errorDNSReload', info: '' });
				output.error("Resolver 'smartdns' not found");
			}
			return false;
		}
		cfg.allow_non_ascii = false;
		break;
	case 'unbound':
		if (!check_unbound()) {
			if (param != 'quiet') {
				push(status_data.errors, { code: 'errorDNSReload', info: '' });
				output.error("Resolver 'unbound' not found");
			}
			return false;
		}
		cfg.allow_non_ascii = true;
		break;
	}

	// Check specific cfg.dns mode support
	switch (cfg.dns) {
	case 'dnsmasq.ipset':
		if (!check_dnsmasq_feature('ipset')) {
			if (param != 'quiet') push(status_data.errors, { code: 'errorNoDnsmasqIpset', info: '' });
			cfg.dns = 'dnsmasq.servers';
		}
		if (!check_ipset()) {
			if (param != 'quiet') push(status_data.errors, { code: 'errorNoIpset', info: '' });
			cfg.dns = 'dnsmasq.servers';
		}
		break;
	case 'dnsmasq.nftset':
		if (!check_dnsmasq_feature('nftset')) {
			if (param != 'quiet') push(status_data.errors, { code: 'errorNoDnsmasqNftset', info: '' });
			cfg.dns = 'dnsmasq.servers';
		}
		if (!check_nft()) {
			if (param != 'quiet') push(status_data.errors, { code: 'errorNoNft', info: '' });
			cfg.dns = 'dnsmasq.servers';
		}
		break;
	case 'smartdns.ipset':
		if (!check_ipset()) {
			if (param != 'quiet') push(status_data.errors, { code: 'errorNoIpset', info: '' });
			cfg.dns = 'smartdns.domainset';
		}
		break;
	case 'smartdns.nftset':
		if (!check_nft()) {
			if (param != 'quiet') push(status_data.errors, { code: 'errorNoNft', info: '' });
			cfg.dns = 'smartdns.domainset';
		}
		break;
	}

	if (cfg.dnsmasq_config_file_url) {
		cfg.update_config_sizes = false;
		if (cfg.dns != 'dnsmasq.conf') {
			cfg.dns = 'dnsmasq.conf';
			if (param != 'quiet')
				push(status_data.warnings, { code: 'warningExternalDnsmasqConfig', info: '' });
		}
	}

	// Clean up files for non-active cfg.dns modes
	for (let mode in dns_modes) {
		if (mode == cfg.dns) continue;
		let dc = dns_modes[mode];
		unlink(dc.cache);
		unlink(cfg.compressed_cache_dir + '/' + dc.gzip);
		if (dc.file != pkg.dnsmasq_file) unlink(dc.file);
		if (dc.config) unlink(dc.config);
	}

	// Create directories
	let dirs = [pkg.run_file, pkg.status_file, dns_output.file, dns_output.cache, dns_output.gzip, dns_output.config];
	for (let f in dirs) {
		if (!f) continue;
		let dir = dirname(f);
		if (!mkdir_p(dir)) {
			if (param != 'quiet')
				push(status_data.errors, { code: 'errorOutputDirCreate', info: f });
		}
	}

	if (is_present('gawk')) state.awk_cmd = 'gawk';
	if (!is_present('/usr/libexec/grep-gnu') || !is_present('/usr/libexec/sed-gnu') ||
		!is_present('/usr/libexec/sort-coreutils') || !is_present('gawk')) {
		let s = '';
		if (!is_present('gawk')) { push(status_data.warnings, { code: 'warningMissingRecommendedPackages', info: 'gawk' }); s += (s ? ' ' : '') + 'gawk'; }
		if (!is_present('/usr/libexec/grep-gnu')) { push(status_data.warnings, { code: 'warningMissingRecommendedPackages', info: 'grep' }); s += (s ? ' ' : '') + 'grep'; }
		if (!is_present('/usr/libexec/sed-gnu')) { push(status_data.warnings, { code: 'warningMissingRecommendedPackages', info: 'sed' }); s += (s ? ' ' : '') + 'sed'; }
		if (!is_present('/usr/libexec/sort-coreutils')) { push(status_data.warnings, { code: 'warningMissingRecommendedPackages', info: 'coreutils-sort' }); s += (s ? ' ' : '') + 'coreutils-sort'; }
		if (param != 'quiet') {
			output.warning(get_text('warningMissingRecommendedPackages') + ', install them by running:');
			output.print('opkg update; opkg --force-overwrite install ' + s + ';');
		}
	}

	load_dl_command();
	if (cfg.led) cfg.led = '/sys/class/leds/' + cfg.led;
	append_urls();
	state.environment_loaded = true;

	if (adb_file('test_cache')) return true;
	if (adb_file('test_gzip')) return true;
	if (param == 'on_boot')
		return load_network(param);
	return true;
}

// ── resolver ────────────────────────────────────────────────────────

function _dnsmasq_instance_get_confdir(inst) {
	// Get the UCI section name for this instance
	let uci_name = uci('dhcp').get('dhcp', inst, '.name') || inst;
	// Cache dnsmasq service info via ubus
	if (!state.dnsmasq_ubus) {
		let ub = connect();
		if (ub) {
			state.dnsmasq_ubus = ub.call('service', 'list', { name: 'dnsmasq' });
			ub.disconnect();
		}
	}
	// Extract the -C config file from the dnsmasq instance command line
	let cfg_file = null;
	let cmd_arr = state.dnsmasq_ubus?.dnsmasq?.instances?.[uci_name]?.command;
	if (type(cmd_arr) == 'array') {
		for (let i = 0; i < length(cmd_arr); i++)
			if (cmd_arr[i] == '-C' && i + 1 < length(cmd_arr)) { cfg_file = cmd_arr[i + 1]; break; }
	}
	if (!cfg_file) return null;
	// Parse conf-dir from the dnsmasq config file
	let content = readfile(cfg_file) || '';
	if (!content) return null;
	for (let line in split(content, '\n')) {
		let m = match(line, /^conf-dir=(.+)$/);
		if (m) return m[1];
	}
	return null;
}

function _dnsmasq_instance_config(inst, param) {
	if (!stat('/etc/config/dhcp')?.size) return;
	let dhcp = uci('dhcp');
	if (!dhcp.get('dhcp', inst)) return;
	let confdir;
	let addnhostsFile = dns_modes['dnsmasq.addnhosts'].file;
	let confFile = dns_modes['dnsmasq.conf'].file;
	let serversFile = dns_modes['dnsmasq.servers'].file;
	switch (param) {
	case 'dnsmasq.addnhosts':
		confdir = _dnsmasq_instance_get_confdir(inst);
		if (confdir) unlink(confdir + '/' + pkg.name);
		dhcp.list_remove('dhcp', inst, 'addnmount', confFile);
		if (dhcp.get('dhcp', inst, 'serversfile') == serversFile)
			dhcp.delete('dhcp', inst, 'serversfile');
		uci_list_add_if_new('dhcp', inst, 'addnhosts', addnhostsFile);
		break;
	case 'cleanup':
	case 'unbound.adb_list':
		confdir = _dnsmasq_instance_get_confdir(inst);
		if (confdir) unlink(confdir + '/' + pkg.name);
		dhcp.list_remove('dhcp', inst, 'addnhosts', addnhostsFile);
		dhcp.list_remove('dhcp', inst, 'addnmount', confFile);
		if (dhcp.get('dhcp', inst, 'serversfile') == serversFile)
			dhcp.delete('dhcp', inst, 'serversfile');
		break;
	case 'dnsmasq.conf':
	case 'dnsmasq.ipset':
	case 'dnsmasq.nftset':
		dhcp.list_remove('dhcp', inst, 'addnhosts', addnhostsFile);
		if (dhcp.get('dhcp', inst, 'serversfile') == serversFile)
			dhcp.delete('dhcp', inst, 'serversfile');
		uci_list_add_if_new('dhcp', inst, 'addnmount', confFile);
		confdir = _dnsmasq_instance_get_confdir(inst);
		if (!confdir) { dhcp.save('dhcp'); return; }
		unlink(confdir + '/' + pkg.name);
		symlink(confFile, confdir + '/' + pkg.name);
		chmod(confdir + '/' + pkg.name, 0660);
		chown(confdir + '/' + pkg.name, 'root', 'dnsmasq');
		break;
	case 'dnsmasq.servers':
		dhcp.list_remove('dhcp', inst, 'addnhosts', addnhostsFile);
		confdir = _dnsmasq_instance_get_confdir(inst);
		if (confdir) unlink(confdir + '/' + pkg.name);
		dhcp.list_remove('dhcp', inst, 'addnmount', confFile);
		if (dhcp.get('dhcp', inst, 'serversfile') != serversFile)
			dhcp.set('dhcp', inst, 'serversfile', serversFile);
		break;
	}
	dhcp.save('dhcp');
}

function _dnsmasq_instance_append_force_dns_port(inst) {
	if (!stat('/etc/config/dhcp')?.size) return;
	let dhcp = uci('dhcp');
	if (!dhcp.get('dhcp', inst)) return;
	let instance_port = dhcp.get('dhcp', inst, 'port') ?? '53';
	if (!str_contains_word(cfg.force_dns_port, instance_port))
		cfg.force_dns_port = (cfg.force_dns_port ? cfg.force_dns_port + ' ' : '') + instance_port;
}

function _smartdns_instance_config(inst, param) {
	if (!stat('/etc/config/smartdns')?.size) return;
	let sdns = uci('smartdns');
	if (!sdns.get('smartdns', inst)) return;
	switch (param) {
	case 'cleanup':
		sdns.list_remove('smartdns', inst, 'conf_files', dns_output.config);
		sdns.save('smartdns');
		unlink(dns_output.config);
		break;
	case 'smartdns.domainset':
		writefile(dns_output.config,
			'domain-set -name adblock-fast -file ' + dns_output.file + '\n' +
			'domain-rules /domain-set:adblock-fast/ -a #\n');
		uci_list_add_if_new('smartdns', inst, 'conf_files', dns_output.config);
		break;
	case 'smartdns.ipset':
		writefile(dns_output.config,
			'domain-set -name adblock-fast -file ' + dns_output.file + '\n' +
			'domain-rules /domain-set:adblock-fast/ -ipset adb\n');
		uci_list_add_if_new('smartdns', inst, 'conf_files', dns_output.config);
		break;
	case 'smartdns.nftset':
		let nftset = '#4:inet#fw4#adb4';
		if (cfg.ipv6_enabled) nftset += ',#6:inet#fw4#adb6';
		writefile(dns_output.config,
			'domain-set -name adblock-fast -file ' + dns_output.file + '\n' +
			'domain-rules /domain-set:adblock-fast/ -nftset ' + nftset + '\n');
		uci_list_add_if_new('smartdns', inst, 'conf_files', dns_output.config);
		break;
	}
}

function _smartdns_instance_append_force_dns_port(inst) {
	if (!stat('/etc/config/smartdns')?.size) return;
	let sdns = uci('smartdns');
	if (!sdns.get('smartdns', inst)) return;
	let instance_port = sdns.get('smartdns', inst, 'port') ?? '53';
	if (!str_contains_word(cfg.force_dns_port, instance_port))
		cfg.force_dns_port = (cfg.force_dns_port ? cfg.force_dns_port + ' ' : '') + instance_port;
}

function _unbound_instance_append_force_dns_port(inst) {
	if (!stat('/etc/config/unbound')?.size) return;
	let ubnd = uci('unbound');
	if (!ubnd.get('unbound', inst)) return;
	let instance_port = ubnd.get('unbound', inst, 'listen_port') ?? '53';
	if (!str_contains_word(cfg.force_dns_port, instance_port))
		cfg.force_dns_port = (cfg.force_dns_port ? cfg.force_dns_port + ' ' : '') + instance_port;
}

function _get_dnsmasq_instances() {
	let result = [];
	let dhcp_cur = cursor();
	dhcp_cur.load('dhcp');
	if (cfg.dnsmasq_instance == '*') {
		dhcp_cur.foreach('dhcp', 'dnsmasq', (s) => push(result, s['.name']));
	} else if (cfg.dnsmasq_instance) {
		for (let inst in split('' + cfg.dnsmasq_instance, /\s+/)) {
			if (!inst) continue;
			// Try @dnsmasq[N] index style, resolve to section name
			let s = dhcp_cur.get_all('dhcp', '@dnsmasq[' + inst + ']');
			push(result, s?.['.name'] || inst);
		}
	}
	return result;
}

function _get_smartdns_instances() {
	let result = [];
	let sdns_cur = cursor();
	sdns_cur.load('smartdns');
	if (cfg.smartdns_instance == '*') {
		sdns_cur.foreach('smartdns', 'smartdns', (s) => push(result, s['.name']));
	} else if (cfg.smartdns_instance) {
		for (let inst in split('' + cfg.smartdns_instance, /\s+/)) {
			if (!inst) continue;
			let s = sdns_cur.get_all('smartdns', '@smartdns[' + inst + ']');
			push(result, s?.['.name'] || inst);
		}
	}
	return result;
}

function resolver(action) {
	let resolver_name = split(cfg.dns || '', '.')[0];
	if (!action) return true;

	switch (action) {
	case 'cleanup':
		for (let mode in dns_modes) {
			let dc = dns_modes[mode];
			unlink(dc.cache);
			unlink(cfg.compressed_cache_dir + '/' + dc.gzip);
			if (dc.file != pkg.dnsmasq_file) unlink(dc.file);
			if (dc.config) unlink(dc.config);
		}
		if (stat('/etc/config/dhcp')?.size) {
			for (let name in _get_dnsmasq_instances())
				_dnsmasq_instance_config(name, 'cleanup');
			if (uci_has_changes('dhcp')) uci('dhcp').commit('dhcp');
		}
		if (stat('/etc/config/smartdns')?.size) {
			for (let name in _get_smartdns_instances())
				_smartdns_instance_config(name, 'cleanup');
			if (uci_has_changes('smartdns')) uci('smartdns').commit('smartdns');
		}
		break;

	case 'on_stop':
	case 'quiet':
	case 'quiet_restart':
		return service_restart(resolver_name);

	case 'on_start':
		if (!adb_file('test')) {
			status_data.status = 'statusFail';
			push(status_data.errors, { code: 'errorOutputFileCreate', info: dns_output.file });
			return false;
		}
		output.info('Cycling ' + resolver_name + ' ');
		if (resolver('update_config') && resolver('test') && resolver('sanity') && resolver('restart') && resolver('heartbeat')) {
			// success
		} else {
			resolver('revert');
		}
		output.info('\\n');
		break;

	case 'test':
		switch (cfg.dns) {
		case 'dnsmasq.addnhosts':
		case 'dnsmasq.conf':
		case 'dnsmasq.ipset':
		case 'dnsmasq.nftset':
		case 'dnsmasq.servers':
			output.dns('Testing ' + cfg.dns + ' configuration ');
			if (cmd_rc('dnsmasq --test') == 0) {
				output.ok();
				return true;
			}
			output.fail();
			return false;
		default:
			return true;
		}

	case 'restart':
		output.dns('Restarting ' + resolver_name + ' ');
		status_data.message = 'Restarting ' + resolver_name;
		if (service_restart(resolver_name)) {
			status_data.status = 'statusSuccess';
			led_on(cfg.led);
			output.ok();
			return true;
		}
		output.fail();
		status_data.status = 'statusFail';
		push(status_data.errors, { code: 'errorDNSReload', info: '' });
		return false;

	case 'sanity':
		if (!cfg.dnsmasq_sanity_check) return true;
		output.dns('Sanity check for ' + cfg.dns + ' TLDs ');
		if (!grep_test('\\.|server:', dns_output.file, '-qvE')) {
			output.ok();
		} else {
			push(status_data.warnings, { code: 'warningSanityCheckTLD', info: dns_output.file });
			output.warn();
		}
		output.dns('Sanity check for ' + cfg.dns + ' leading dots ');
		let dot_pattern;
		switch (split(cfg.dns, '.')[0]) {
		case 'dnsmasq': dot_pattern = '/\\.'; break;
		case 'smartdns': dot_pattern = '^\\.'; break;
		case 'unbound': dot_pattern = '"\\.'; break;
		}
		if (dot_pattern && !grep_test(dot_pattern, dns_output.file)) {
			output.ok();
		} else {
			push(status_data.warnings, { code: 'warningSanityCheckLeadingDot', info: dns_output.file });
			output.warn();
		}
		return true;

	case 'heartbeat':
		if (!cfg.heartbeat_domain) return true;
		if (!is_integer(cfg.heartbeat_sleep_timeout)) return true;
		output.dns('Probing ' + cfg.heartbeat_domain + ' for ' + cfg.heartbeat_sleep_timeout + ' seconds ');
		status_data.message = 'Testing resolver on ' + cfg.heartbeat_domain;
		let timeout = int(cfg.heartbeat_sleep_timeout);
		for (let i = 0; i < timeout; i++) {
			if (cmd_rc('resolveip ' + shell_quote(cfg.heartbeat_domain)) == 0) {
				output.ok();
				return true;
			}
			output.dot();
			system('sleep 1');
		}
		output.fail();
		status_data.status = 'statusFail';
		push(status_data.errors, { code: 'errorNoHeartbeat', info: '' });
		return false;

	case 'revert':
		output.info('Resetting/Restarting ' + resolver_name + ' ');
		output.dns('Resetting ' + resolver_name + ' ');
		resolver('cleanup');
		output.ok();
		output.dns('Restarting ' + resolver_name + ' ');
		if (service_restart(resolver_name)) {
			led_off(cfg.led);
			output.ok();
			return true;
		}
		output.fail();
		status_data.status = 'statusFail';
		push(status_data.errors, { code: 'errorDNSReload', info: '' });
		return false;

	case 'update_config':
		output.dns('Updating ' + resolver_name + ' configuration ');
		switch (split(cfg.dns, '.')[0]) {
		case 'dnsmasq':
			for (let name in _get_dnsmasq_instances()) {
				_dnsmasq_instance_config(name, cfg.dns);
				_dnsmasq_instance_append_force_dns_port(name);
			}
			if (uci_has_changes('dhcp')) uci('dhcp').commit('dhcp');
			if (adb_file('test')) {
				chmod(dns_output.file, 0660);
				chown(dns_output.file, 'root', 'dnsmasq');
			} else {
				status_data.status = 'statusFail';
				push(status_data.errors, { code: 'errorNoOutputFile', info: dns_output.file });
				return false;
			}
			break;
		case 'smartdns':
			for (let name in _get_smartdns_instances()) {
				_smartdns_instance_config(name, cfg.dns);
				_smartdns_instance_append_force_dns_port(name);
			}
			if (uci_has_changes('smartdns')) uci('smartdns').commit('smartdns');
			chmod(dns_output.file, 0660);
			chmod(dns_output.config, 0660);
			chown(dns_output.file, 'root', 'root');
			chown(dns_output.config, 'root', 'root');
			break;
		case 'unbound':
			let ubnd_cur = cursor();
			ubnd_cur.load('unbound');
			ubnd_cur.foreach('unbound', 'unbound', (s) => _unbound_instance_append_force_dns_port(s['.name']));
			chmod(dns_output.file, 0660);
			chown(dns_output.file, 'root', 'unbound');
			break;
		}
		output.ok();
		return true;
	}
	return true;
}

// ── process_file_url ────────────────────────────────────────────────

function process_file_url(section, url_override, action_override) {
	let url, file_action, name, size_val;

	if (section && !url_override) {
		let sec_cur = cursor();
		sec_cur.load(pkg.name);
		let en = sec_cur.get(pkg.name, section, 'enabled');
		if (en == '0') return true;
		url = sec_cur.get(pkg.name, section, 'url');
		file_action = sec_cur.get(pkg.name, section, 'action') || 'block';
		name = sec_cur.get(pkg.name, section, 'name');
		size_val = sec_cur.get(pkg.name, section, 'size');
	} else {
		url = url_override;
		file_action = action_override || 'block';
	}

	if (!cfg.enabled) return true;
	if (!url) return false;

	let label = replace(url, /^[a-z]+:\/\//, '');
	label = replace(label, /\/.*$/, '');
	label = name || label;
	label = 'List: ' + label;

	let type_name, d_tmp;
	switch (file_action) {
	case 'allow': type_name = 'Allowed'; d_tmp = tmp.allowed; break;
	case 'block': type_name = 'Blocked'; d_tmp = tmp.b; break;
	case 'file': type_name = 'File'; d_tmp = tmp.b; break;
	}

	if (is_https_url(url) && !state.ssl_supported) {
		output.info(sym.fail[0]);
		output.verbose('[ DL ] ' + type_name + ' ' + label + ' ' + sym.fail[1] + '\\n');
		push(status_data.errors, { code: 'errorNoSSLSupport', info: name || url });
		return true;
	}

	let r_tmp = trim(cmd_output('mktemp -q -t "' + pkg.name + '_tmp.XXXXXXXX"'));
	if (!url || !download(url, r_tmp) || !(stat(r_tmp)?.size > 0)) {
		output.info(sym.fail[0]);
		output.verbose('[ DL ] ' + type_name + ' ' + label + ' ' + sym.fail[1] + '\\n');
		push(status_data.errors, { code: 'errorDownloadingList', info: name || url });
	} else {
		// Ensure newline at end
		ensure_trailing_newline(r_tmp);

		// Update size in config if changed
		if (section) {
			let new_size = get_local_filesize(r_tmp);
			if (new_size != null && ('' + size_val) != ('' + new_size))
				uci(pkg.name).set(pkg.name, section, 'size', '' + new_size);
			uci(pkg.name).save(pkg.name);
		}

		let format = detect_file_type(r_tmp);
		let filter = list_formats[format]?.filter;
		if (!filter) {
			output.info(sym.fail[0]);
			output.verbose('[ DL ] ' + type_name + ' ' + label + ' ' + sym.fail[1] + '\\n');
			push(status_data.errors, { code: 'errorDetectingFileType', info: name || url });
			unlink(r_tmp);
			return true;
		}
		if (format == 'hosts')
			sed_inplace('/# Title: StevenBlack/,/# Custom host records are listed here/d', r_tmp);

		if (filter && file_action != 'file')
			sed_inplace(filter, r_tmp);

		if (!(stat(r_tmp)?.size > 0)) {
			output.info(sym.fail[0]);
			output.verbose('[ DL ] ' + type_name + ' ' + label + ' (' + format + ') ' + sym.fail[1] + '\\n');
			push(status_data.errors, { code: 'errorParsingList', info: name || url });
		} else {
			// Ensure file ends with newline, then append to accumulator
			ensure_trailing_newline(r_tmp);
			let inp = open(r_tmp, 'r');
			let out = open(d_tmp, 'a');
			if (inp && out) {
				let chunk;
				while ((chunk = inp.read(65536)) && length(chunk))
					out.write(chunk);
			}
			if (inp) inp.close();
			if (out) out.close();
			output.info(sym.ok[0]);
			output.verbose('[ DL ] ' + type_name + ' ' + label + ' (' + format + ') ' + sym.ok[1] + '\\n');
		}
	}
	unlink(r_tmp);
	return true;
}

// ── download_dnsmasq_file ───────────────────────────────────────────

function download_dnsmasq_file() {
	status_data.message = get_text('statusDownloading') + '...';
	status_data.status = 'statusDownloading';

	for (let f in [tmp.allowed, tmp.a, tmp.b, tmp.sed, dns_output.file, dns_output.cache]) unlink(f);
	if (get_mem_available() < pkg.memory_threshold) {
		output.print('Low free memory, restarting resolver ');
		if (resolver('quiet_restart')) output.okn(); else output.failn();
	}
	for (let f in [tmp.allowed, tmp.a, tmp.b, tmp.sed]) writefile(f, '');
	output.info('Downloading dnsmasq file ');
	process_file_url(null, cfg.dnsmasq_config_file_url, 'file');
	output.dns('Moving dnsmasq file ');
	if (rename(tmp.b, dns_output.file)) {
		output.ok();
	} else {
		output.fail();
		push(status_data.errors, { code: 'errorMovingDataFile', info: dns_output.file });
	}
	output.info('\\n');
}

// ── download_lists ──────────────────────────────────────────────────

function download_lists() {
	// RAM check
	let free_mem = get_mem_available();
	if (!free_mem) {
		push(status_data.warnings, { code: 'warningFreeRamCheckFail', info: '' });
		output.warning(get_text('warningFreeRamCheckFail'));
	} else {
		let total_sizes = 0;
		uci(pkg.name).foreach(pkg.name, 'file_url', (s) => {
			if (s.enabled == '0') return;
			let sz = s.size;
			if (!sz && s.url) sz = get_url_filesize(s.url);
			if (sz) total_sizes += int('' + sz);
		});
		if (free_mem < total_sizes * 2) {
			push(status_data.errors, { code: 'errorTooLittleRam', info: '' + free_mem });
			return false;
		}
	}

	status_data.message = get_text('statusDownloading') + '...';
	status_data.status = 'statusDownloading';

	for (let f in [tmp.allowed, tmp.a, tmp.b, tmp.sed, dns_output.file, dns_output.cache, dns_output.gzip]) unlink(f);
	if (get_mem_total() < pkg.memory_threshold) {
		output.print('Low free memory, restarting resolver ');
		if (resolver('quiet_restart')) output.okn(); else output.failn();
	}
	for (let f in [tmp.allowed, tmp.a, tmp.b, tmp.sed]) writefile(f, '');

	output.info('Downloading lists ');

	// Process each file_url section
	let download_cfgs = [];
	uci(pkg.name).foreach(pkg.name, 'file_url', (s) => push(download_cfgs, s['.name']));

	for (let cfg_name in download_cfgs)
		process_file_url(cfg_name);

	if (uci_has_changes(pkg.name)) {
		output.verbose('[PROC] Saving updated file sizes ');
		if (cfg.update_config_sizes && uci(pkg.name).commit(pkg.name))
			output.ok();
		else
			output.fail();
	}
	output.info('\\n');

	// Add canary domains and cfg.blocked_domain
	let canaryDomains = '';
	if (cfg.canary_domains_icloud)
		canaryDomains += (canaryDomains ? ' ' : '') + canary.icloud;
	if (cfg.canary_domains_mozilla)
		canaryDomains += (canaryDomains ? ' ' : '') + canary.mozilla;

	output.info('Processing downloads ');

	let start_time, end_time, elapsed, step_title;

	// Sort combined block-list
	start_time = time();
	step_title = 'Sorting combined block-list';
	output.verbose('[PROC] ' + step_title + ' ');
	status_data.status = 'statusProcessing';
	status_data.message = get_text('statusProcessing') + ': ' + step_title;

	// Append cfg.blocked_domain and canary domains
	ensure_trailing_newline(tmp.b);
	let extra_domains = '';
	for (let hf in split((cfg.blocked_domain || '') + ' ' + canaryDomains, /\s+/)) {
		if (hf) extra_domains += hf + '\n';
	}
	if (extra_domains) {
		let fd = popen(sprintf("sed %s >> %s", shell_quote(list_formats.domains.filter), shell_quote(tmp.b)), 'w');
		if (fd) { fd.write(extra_domains); fd.close(); }
	}
	sed_inplace('/^[[:space:]]*$/d', tmp.b);

	if (!(stat(tmp.b)?.size > 0)) return false;

	if (cfg.allow_non_ascii) {
		if (sort_file(tmp.b, tmp.a, true))
			output.ok();
		else { output.fail(); push(status_data.errors, { code: 'errorSorting', info: '' }); }
	} else {
		if (system(sprintf("sort -u %s | grep -E -v '[^a-zA-Z0-9=/.-]' > %s", shell_quote(tmp.b), shell_quote(tmp.a))) == 0)
			output.ok();
		else { output.fail(); push(status_data.errors, { code: 'errorSorting', info: '' }); }
	}
	end_time = time();
	elapsed = end_time - start_time;
	logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');

	// Optimization (subdomain dedup)
	let needs_optimization = (cfg.dns == 'dnsmasq.conf' || cfg.dns == 'dnsmasq.ipset' || cfg.dns == 'dnsmasq.nftset' ||
		cfg.dns == 'dnsmasq.servers' || cfg.dns == 'smartdns.domainset' || cfg.dns == 'smartdns.ipset' ||
		cfg.dns == 'smartdns.nftset' || cfg.dns == 'unbound.adb_list');

	if (needs_optimization) {
		start_time = time();
		step_title = 'Optimizing combined block-list';
		output.verbose('[PROC] ' + step_title + ' ');
		status_data.message = get_text('statusProcessing') + ': ' + step_title;

		let ok = awk_reverse_labels(tmp.a, tmp.b);
		if (ok) ok = sort_file(tmp.b, tmp.a);
		if (ok) ok = awk_dedup_subdomains(tmp.a, tmp.b);
		if (ok) ok = awk_reverse_labels(tmp.b, tmp.a);
		if (ok) ok = sort_file(tmp.a, tmp.b, true);
		if (ok) { output.ok(); }
		else {
			output.fail();
			push(status_data.errors, { code: 'errorOptimization', info: '' });
			rename(tmp.a, tmp.b);
		}
		end_time = time();
		elapsed = end_time - start_time;
		logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');
	} else {
		rename(tmp.a, tmp.b);
	}

	// Remove allowed domains
	if (cfg.allowed_domain || (stat(tmp.allowed)?.size > 0)) {
		start_time = time();
		step_title = 'Removing allowed domains from combined block-list';
		output.verbose('[PROC] ' + step_title + ' ');
		status_data.message = get_text('statusProcessing') + ': ' + step_title;

		let allowed_extra = '';
		if (stat(tmp.allowed)?.size > 0)
			allowed_extra = trim(cmd_output(sprintf("sed '/^[[:space:]]*$/d' %s", shell_quote(tmp.allowed))));
		let all_allowed = (cfg.allowed_domain || '') + (allowed_extra ? ' ' + allowed_extra : '');

		let sed_content = '';
		for (let hf in split(all_allowed, /\s+/)) {
			if (!hf) continue;
			let escaped = replace(hf, /\./g, '\\.');
			sed_content += '/(^|\\.)' + escaped + '$/d;\n';
		}
		if (sed_content) {
			writefile(tmp.sed, sed_content);
			if (sed_script(tmp.sed, tmp.b, tmp.a) && rename(tmp.a, tmp.b))
				output.ok();
			else { output.fail(); push(status_data.errors, { code: 'errorAllowListProcessing', info: '' }); }
		} else {
			output.fail();
			push(status_data.errors, { code: 'errorAllowListProcessing', info: '' });
		}
		end_time = time();
		elapsed = end_time - start_time;
		logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');
	}

	// Format combined block-list
	start_time = time();
	step_title = 'Formatting combined block-list file';
	output.verbose('[PROC] ' + step_title + ' ');
	status_data.message = get_text('statusProcessing') + ': ' + step_title;

	if (!dns_output.filter_ipv6) {
		if (dns_output.filter) {
			if (sed_filter(dns_output.filter, tmp.b, tmp.a))
				output.ok();
			else { output.fail(); push(status_data.errors, { code: 'errorDataFileFormatting', info: '' }); }
		} else {
			writefile(tmp.a, readfile(tmp.b) || '');
			output.ok();
		}
	} else {
		if (cfg.dns == 'dnsmasq.addnhosts') {
			if (sed_filter(dns_output.filter, tmp.b, tmp.a) &&
				system(sprintf('sed %s %s >> %s', shell_quote(dns_output.filter_ipv6), shell_quote(tmp.b), shell_quote(tmp.a))) == 0)
				output.ok();
			else { output.fail(); push(status_data.errors, { code: 'errorDataFileFormatting', info: '' }); }
		}
	}
	end_time = time();
	elapsed = end_time - start_time;
	logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');

	// Explicitly allow domains in servers mode
	if (dns_output.allow_filter && cfg.allowed_domain) {
		unlink(tmp.sed); writefile(tmp.sed, '');
		start_time = time();
		step_title = 'Explicitly allowing domains in ' + cfg.dns;
		output.verbose('[PROC] ' + step_title + ' ');
		status_data.message = get_text('statusProcessing') + ': ' + step_title;
		let allow_input = '';
		for (let hf in split('' + cfg.allowed_domain, /\s+/))
			if (hf) allow_input += hf + '\n';
		if (allow_input)
			system(sprintf("printf '%%s' %s | sed -E '%s' >> %s", shell_quote(allow_input), dns_output.allow_filter, shell_quote(tmp.sed)));
		if (stat(tmp.sed)?.size > 0) {
			if (writefile(tmp.b, (readfile(tmp.sed) || '') + (readfile(tmp.a) || '')))
				output.ok();
			else { output.fail(); push(status_data.errors, { code: 'errorAllowListProcessing', info: '' }); }
		} else {
			output.fail();
			push(status_data.errors, { code: 'errorAllowListProcessing', info: '' });
		}
		end_time = time();
		elapsed = end_time - start_time;
		logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');
	} else {
		rename(tmp.a, tmp.b);
	}

	// Move to output file
	start_time = time();
	step_title = 'Setting up ' + cfg.dns + ' file';
	output.verbose('[PROC] ' + step_title + ' ');
	status_data.message = get_text('statusProcessing') + ': ' + step_title;

	if (rename(tmp.b, dns_output.file)) {
		output.ok();
	} else {
		output.fail();
		push(status_data.errors, { code: 'errorMovingDataFile', info: dns_output.file });
	}
	if (cfg.dns == 'unbound.adb_list')
		sed_inplace('1 i\\server:', dns_output.file);

	// Validity check
	if (cfg.dnsmasq_validity_check && index(cfg.dns, 'dnsmasq.') == 0) {
		start_time = time();
		step_title = 'Validating domain entries';
		output.verbose('[PROC] ' + step_title + ' ');
		status_data.message = get_text('statusProcessing') + ': ' + step_title;
		let invalid_file = '/tmp/' + pkg.name + '.invalid.tmp';
		unlink(invalid_file);
		system(sprintf("sed '%s' %s | grep -E '^-|^\\.|^[0-9.]+$|\\.\\.|\\-$|\\.$' > %s 2>/dev/null || true",
			dns_output.parse_filter, shell_quote(dns_output.file), shell_quote(invalid_file)));
		let invalid_count = 0;
		if (stat(invalid_file)?.size > 0) {
			invalid_count = int(trim(cmd_output('wc -l < ' + shell_quote(invalid_file))) || '0');
			if (invalid_count > 0) {
				let dc = dns_modes[cfg.dns];
				let grep_pat = dc ? dc.grep_pattern : null;
				if (cfg.dns == 'dnsmasq.addnhosts' && dc) {
					system(sprintf("{ sed '%s' %s; sed '%s' %s; } > %s.pat 2>/dev/null",
						dc.grep_pattern_ipv4, shell_quote(invalid_file),
						dc.grep_pattern_ipv6, shell_quote(invalid_file),
						shell_quote(invalid_file)));
					grep_pat = null;
				}
				if (grep_pat)
					sed_filter(grep_pat, invalid_file, invalid_file + '.pat');
				grep_exclude_file(invalid_file + '.pat', dns_output.file, dns_output.file + '.valid');
				rename(dns_output.file + '.valid', dns_output.file);
				logger(sprintf('Removed %d invalid entries from %s.', invalid_count, cfg.dns));
				push(status_data.warnings, { code: 'warningInvalidDomainsRemoved', info: '' + invalid_count });
				unlink(invalid_file + '.pat');
			}
			unlink(invalid_file);
		}
		if (invalid_count > 0) output.warn(); else output.ok();
		end_time = time();
		elapsed = end_time - start_time;
		logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');
	}

	// Remove temporary files
	step_title = 'Removing temporary files';
	output.verbose('[PROC] ' + step_title + ' ');
	status_data.message = get_text('statusProcessing') + ': ' + step_title;
	for (let f in glob('/tmp/' + pkg.name + '_tmp.*') || []) unlink(f);
	for (let f in [tmp.allowed, tmp.a, tmp.b, tmp.sed, dns_output.cache]) unlink(f);
	output.ok();
	output.info('\\n');
	return true;
}

// ── adb_config_update ───────────────────────────────────────────────

function adb_config_update(param) {
	param = param || 'quiet';
	load();
	load_dl_command();
	let label = replace('' + cfg.config_update_url, /^[a-z]+:\/\//, '');
	label = replace(label, /\/.*$/, '');
	if (!cfg.enabled) return;
	if (!cfg.config_update_enabled) return;

	if (param != 'download') {
		if (adb_file('test')) return;
		if (adb_file('test_cache')) return;
		if (adb_file('test_gzip')) return;
	}

	output.info('Updating config ');
	output.verbose('[ DL ] Config Update: ' + label + ' ');
	let r_tmp = trim(cmd_output('mktemp -q -t "' + pkg.name + '_tmp.XXXXXXXX"'));
	if (!download(cfg.config_update_url, r_tmp) || !(stat(r_tmp)?.size > 0)) {
		output.failn();
		push(status_data.errors, { code: 'errorDownloadingConfigUpdate', info: '' });
	} else {
		if (system(sprintf("sed -f %s -i %s 2>/dev/null", shell_quote(r_tmp), shell_quote(pkg.config_file))) == 0)
			output.okn();
		else { output.failn(); push(status_data.errors, { code: 'errorParsingConfigUpdate', info: '' }); }
	}
	unlink(r_tmp);
	// Cleanup missing URLs (refresh cursor after sed modified config)
	let to_delete = [];
	uci(pkg.name, true).foreach(pkg.name, 'file_url', (s) => {
		if (!s.url) push(to_delete, s['.name']);
	});
	for (let name in to_delete)
		uci(pkg.name).delete(pkg.name, name);
	uci(pkg.name).save(pkg.name);
	if (uci_has_changes(pkg.name))
		uci(pkg.name).commit(pkg.name);
}

// ── _build_procd_data ───────────────────────────────────────────────

function _build_procd_data() {
	let result = {};
	result.version = pkg.version;
	result.status = status_data.status;
	result.packageCompat = int(pkg.compat);
	result.entries = int(count_blocked_domains());

	// Errors
	result.errors = [];
	for (let e in status_data.errors)
		push(result.errors, { code: e.code, info: e.info });

	// Warnings
	result.warnings = [];
	for (let e in status_data.warnings)
		push(result.warnings, { code: e.code, info: e.info });

	// Firewall rules
	result.firewall = [];
	if (cfg.force_dns) {
		let ports = split(replace('' + (cfg.force_dns_port || ''), /,/g, ' '), /\s+/);
		for (let p in ports) {
			if (!p) continue;
			let ifaces = split('' + (cfg.force_dns_interface || ''), /\s+/);
			if (is_port_listening(p)) {
				for (let iface in ifaces) {
					if (!iface) continue;
					push(result.firewall, {
						type: 'redirect', target: 'DNAT', src: iface,
						proto: 'tcp udp', src_dport: '53', dest_port: '' + p,
						family: 'any', reflection: false,
					});
				}
			} else {
				for (let iface in ifaces) {
					if (!iface) continue;
					push(result.firewall, {
						type: 'rule', src: iface, dest: '*',
						proto: 'tcp udp', dest_port: '' + p, target: 'REJECT',
					});
				}
			}
		}
	}

	// ipset/nftset firewall rules
	switch (cfg.dns) {
	case 'dnsmasq.ipset':
	case 'smartdns.ipset':
		push(result.firewall, { type: 'ipset', name: 'adb', match: 'dest_net', storage: 'hash' });
		for (let iface in split('' + (cfg.force_dns_interface || ''), /\s+/)) {
			if (!iface) continue;
			push(result.firewall, { type: 'rule', ipset: 'adb', src: iface, dest: '*', proto: 'tcp udp', target: 'REJECT' });
		}
		break;
	case 'dnsmasq.nftset':
	case 'smartdns.nftset':
		push(result.firewall, { type: 'ipset', name: 'adb4', family: '4', match: 'dest_net' });
		for (let iface in split('' + (cfg.force_dns_interface || ''), /\s+/)) {
			if (!iface) continue;
			push(result.firewall, { type: 'rule', ipset: 'adb4', src: iface, dest: '*', proto: 'tcp udp', target: 'REJECT' });
		}
		if (cfg.ipv6_enabled) {
			push(result.firewall, { type: 'ipset', name: 'adb6', family: '6', match: 'dest_net' });
			for (let iface in split('' + (cfg.force_dns_interface || ''), /\s+/)) {
				if (!iface) continue;
				push(result.firewall, { type: 'rule', ipset: 'adb6', src: iface, dest: '*', proto: 'tcp udp', target: 'REJECT' });
			}
		}
		break;
	}

	return result;
}

// ── emit_procd_shell ────────────────────────────────────────────────
// Converts _build_procd_data() result into json_add_* shell commands
// for safe use between procd_open_data / procd_close_data.

function emit_procd_shell(data) {
	if (!data) return '';
	let lines = [];

	push(lines, 'json_add_string version ' + shell_quote(data.version || ''));
	push(lines, 'json_add_string status ' + shell_quote(data.status || ''));
	push(lines, 'json_add_int packageCompat ' + shell_quote('' + (data.packageCompat || 0)));
	push(lines, 'json_add_int entries ' + shell_quote('' + (data.entries || 0)));

	push(lines, 'json_add_array errors');
	for (let e in (data.errors || [])) {
		push(lines, "json_add_object ''");
		push(lines, 'json_add_string code ' + shell_quote(e.code || ''));
		push(lines, 'json_add_string info ' + shell_quote(e.info || ''));
		push(lines, 'json_close_object');
	}
	push(lines, 'json_close_array');

	push(lines, 'json_add_array warnings');
	for (let w in (data.warnings || [])) {
		push(lines, "json_add_object ''");
		push(lines, 'json_add_string code ' + shell_quote(w.code || ''));
		push(lines, 'json_add_string info ' + shell_quote(w.info || ''));
		push(lines, 'json_close_object');
	}
	push(lines, 'json_close_array');

	push(lines, 'json_add_array firewall');
	for (let rule in (data.firewall || [])) {
		push(lines, "json_add_object ''");
		for (let k in keys(rule)) {
			let v = rule[k];
			if (type(v) == 'bool')
				push(lines, 'json_add_boolean ' + k + ' ' + shell_quote(v ? '1' : '0'));
			else if (type(v) == 'int')
				push(lines, 'json_add_int ' + k + ' ' + shell_quote('' + v));
			else
				push(lines, 'json_add_string ' + k + ' ' + shell_quote('' + v));
		}
		push(lines, 'json_close_object');
	}
	push(lines, 'json_close_array');

	return join('\n', lines) + '\n';
}

// ── status_service ──────────────────────────────────────────────────

function status_service(param) {
	load();
	// When called from start() the in-memory status_data is already correct;
	// reloading from file would overwrite it with stale data.
	if (param != 'on_start_success' && param != 'on_start_failure')
		status_json('load');
	let status = status_data.status;
	let message = status_data.message;
	let stats = status_data.stats;

	if (status == 'statusSuccess') {
		output.info('* ' + stats + '\\n');
		output.verbose('[STAT] ' + stats + '\\n');
	} else {
		if (status) status = get_text(status);
		if (status && message) status += ': ' + message;
		let cache_info = '';
		let has_cache = adb_file('test_cache');
		let has_gzip = adb_file('test_gzip');
		if (has_cache && has_gzip) cache_info = 'cache file and compressed cache file found';
		else if (has_cache) cache_info = 'cache file found';
		else if (has_gzip) cache_info = 'compressed cache file found';
		if (status && cache_info) status += ' (' + cache_info + ')';
		if (status) output.print(pkg.service_name + ' ' + status + '.\\n');
	}

	if (param == 'quiet' || param == 'on_start_success' || param == 'on_start_failure') return;

	for (let e in status_data.errors)
		output.error(get_text(e.code, e.info));
	for (let e in status_data.warnings)
		output.warning(get_text(e.code, e.info));
}

// ── start ───────────────────────────────────────────────────────────
// Returns JSON object for procd_open_data (status, firewall[], errors[], warnings[])

function start(args) {
	let param = (args && args[0]) || 'on_start';

	status_json('load');
	let prev_status = status_data.status;
	let prev_errors = length(status_data.errors) > 0;
	status_json('reset');

	if (param == 'on_boot') {
		if (!adb_file('test_gzip') && !adb_file('test_cache'))
			return null;
	}

	adb_config_update(param);
	if (!load_environment(param)) return null;

	let action = adb_config_cache('get', 'trigger_service');
	state.fw4_restart = adb_config_cache('get', 'trigger_fw4');

	if (prev_errors) {
		action = 'download';
	} else if (!adb_file('test')) {
		if (adb_file('test_gzip') || adb_file('test_cache'))
			action = 'restore';
		else
			action = 'download';
	} else if (prev_status == 'statusSuccess') {
		action = 'skip';
	}

	// Normalize action based on param
	let combo = (action || '') + ':' + param;
	if (index(combo, 'on_boot') >= 0 || param == 'on_pause') {
		action = (adb_file('test_gzip') || adb_file('test_cache')) ? 'restore' : 'download';
	} else if (param == 'download' || action == 'download') {
		action = 'download';
	} else if (action == 'restart') {
		action = 'restart';
	} else if (action == 'restore') {
		action = 'restore';
	} else if (action == 'skip') {
		action = 'skip';
	} else if (!action) {
		action = 'download';
	}

	if (action == 'restore') {
		output.info('Starting ' + pkg.service_name + '...\\n');
		output.verbose('[INIT] Starting ' + pkg.service_name + '...\\n');
		status_data.status = 'statusStarting';
		if (adb_file('test_gzip') && !adb_file('test_cache') && !adb_file('test')) {
			output.info('Found compressed cache file, unpacking it ');
			output.verbose('[INIT] Found compressed cache file, unpacking it ');
			status_data.message = 'found compressed cache file, unpacking it.';
			if (adb_file('unpack_gzip')) {
				output.okn();
			} else {
				output.failn();
				output.error(get_text('errorRestoreCompressedCache'));
				action = 'download';
			}
		}
		if (adb_file('test_cache') && !adb_file('test')) {
			output.info('Found cache file, reusing it ');
			output.verbose('[INIT] Found cache file, reusing it ');
			status_data.message = 'found cache file, reusing it.';
			if (adb_file('restore')) {
				cfg.dnsmasq_sanity_check = false;
				cfg.heartbeat_domain = null;
				output.okn();
				resolver('on_start');
			} else {
				output.failn();
				output.error(get_text('errorRestoreCache'));
				action = 'download';
			}
		}
	}

	if (action == 'download') {
		if (!cfg.blocked_url && !cfg.blocked_domain) {
			status_data.status = 'statusFail';
			push(status_data.errors, { code: 'errorNothingToDo', info: '' });
		} else {
			if (!adb_file('test') || adb_file('test_cache') || adb_file('test_gzip')) {
				output.info('Force-reloading ' + pkg.service_name + '...\\n');
				output.verbose('[INIT] Force-reloading ' + pkg.service_name + '...\\n');
				status_data.status = 'statusForceReloading';
			} else {
				output.info('Starting ' + pkg.service_name + '...\\n');
				output.verbose('[INIT] Starting ' + pkg.service_name + '...\\n');
				status_data.status = 'statusStarting';
			}
			resolver('cleanup');
			if (cfg.dns == 'dnsmasq.conf' && cfg.dnsmasq_config_file_url)
				download_dnsmasq_file();
			else
				download_lists();
			resolver('on_start');
		}
	}

	if (action == 'restart') {
		output.info('Restarting ' + pkg.service_name + '...\\n');
		output.verbose('[INIT] Restarting ' + pkg.service_name + '...\\n');
		status_data.status = 'statusRestarting';
		cfg.dnsmasq_sanity_check = false;
		cfg.heartbeat_domain = null;
		resolver('on_start');
	}

	if (action == 'start') {
		output.info('Starting ' + pkg.service_name + '...\\n');
		output.verbose('[INIT] Starting ' + pkg.service_name + '...\\n');
		status_data.status = 'statusStarting';
		cfg.dnsmasq_sanity_check = false;
		cfg.heartbeat_domain = null;
		resolver('on_start');
	}

	let final_status = status_data.status;
	if (adb_file('test') && final_status != 'statusFail') {
		status_data.message = '';
		status_data.status = 'statusSuccess';
		status_data.stats = pkg.service_name + ' is blocking ' + count_blocked_domains() + ' domains (with ' + cfg.dns + ')';
		status_service('on_start_success');
	} else {
		status_data.status = 'statusFail';
		push(status_data.errors, { code: 'errorOhSnap', info: '' });
		status_service('on_start_failure');
		resolver('revert');
	}

	adb_config_cache('create');

	// Build result object for procd_open_data
	status_json('dump');
	return _build_procd_data();
}

// ── stop ────────────────────────────────────────────────────────────

function stop() {
	load();
	if (adb_file('test')) {
		output.info('Stopping ' + pkg.service_name + '... ');
		output.verbose('[STOP] Stopping ' + pkg.service_name + '... ');
		adb_file('create');
		if (resolver('on_stop')) {
			system('ipset -q -! flush adb 2>/dev/null; ipset -q -! destroy adb 2>/dev/null');
			system('nft delete set inet fw4 adb4 2>/dev/null; nft delete set inet fw4 adb6 2>/dev/null');
			led_off(cfg.led);
			output.okn();
			status_data.status = 'statusStopped';
			status_data.message = '';
		} else {
			output.failn();
			status_data.status = 'statusFail';
			push(status_data.errors, { code: 'errorStopping', info: '' });
			output.error(get_text('errorStopping'));
		}
	}
	status_json('dump');
}

// ── Extra Commands ──────────────────────────────────────────────────

function allow(string) {
	load();
	if (!adb_file('test')) {
		output.print("No block-list ('" + dns_output.file + "') found.\\n");
		return;
	}
	if (!string) {
		output.print("Usage: /etc/init.d/" + pkg.name + " allow 'domain' ...\\n");
		return;
	}
	if (cfg.dnsmasq_config_file_url) {
		output.print("Allowing individual domains is not possible when using external dnsmasq config file.\\n");
		return;
	}

	let resolver_name = split(cfg.dns || '', '.')[0];
	output.info('Allowing domains and restarting ' + resolver_name + ' ');
	output.verbose('[PROC] Allowing domains \\n');

	for (let c in split('' + string, /\s+/)) {
		if (!c) continue;
		output.verbose('  ' + c + ' ');
		let escaped = replace(c, /\./g, '\\.');
		switch (split(cfg.dns, '.')[0]) {
		case 'dnsmasq':
			sed_inplace(sprintf('\\:/\\(/%s\\|.%s\\):d', escaped, escaped), dns_output.file);
			break;
		case 'smartdns':
		case 'unbound':
			sed_inplace(sprintf('\\:\\("%s\\|.%s"\\):d', escaped, escaped), dns_output.file);
			break;
		}
		output.ok();
		if (dns_output.allow_filter) {
			system(sprintf("echo %s | sed -E '%s' >> %s", shell_quote(c), dns_output.allow_filter, shell_quote(dns_output.file)));
			output.ok();
		}
		uci_list_add_if_new(pkg.name, 'config', 'allowed_domain', c);
		output.ok();
	}

	if (cfg.compressed_cache) {
		output.verbose('[PROC] Creating compressed cache ');
		if (adb_file('create_gzip')) output.ok(); else output.fail();
	}
	output.verbose('[PROC] Committing changes to config ');
	if (uci(pkg.name).commit(pkg.name)) {
		let ad = uci(pkg.name).get(pkg.name, 'config', 'allowed_domain');
		cfg.allowed_domain = ad ? replace((type(ad) == 'array') ? join(' ', ad) : '' + ad, /,/g, ' ') : null;
		adb_config_cache('create');
		status_data.stats = pkg.service_name + ' is blocking ' + count_blocked_domains() + ' domains (with ' + cfg.dns + ')';
		output.ok();
		if (cfg.dns == 'dnsmasq.ipset') {
			output.verbose('[PROC] Flushing adb ipset ');
			if (system('ipset -q -! flush adb 2>/dev/null') == 0) output.ok(); else output.fail();
		}
		if (cfg.dns == 'dnsmasq.nftset') {
			output.verbose('[PROC] Flushing adb nft sets ');
			system('nft flush set inet fw4 adb6 2>/dev/null');
			if (system('nft flush set inet fw4 adb4 2>/dev/null') == 0) output.ok(); else output.fail();
		}
		output.dns('Restarting ' + resolver_name + ' ');
		if (service_restart(resolver_name)) output.ok(); else output.fail();
	} else {
		output.fail();
	}
	status_json('dump');
	output.info('\\n');
}

function check(param) {
	load();
	if (!adb_file('test')) {
		output.print("No block-list ('" + dns_output.file + "') found.\\n");
		return;
	}
	if (!param) {
		output.print("Usage: /etc/init.d/" + pkg.name + " check 'domain' ...\\n");
		return;
	}
	for (let string in split('' + param, /\s+/)) {
		if (!string) continue;
		let c = grep_count(string, dns_output.file, '-c -E');
		if (c > 0) {
			let word = (c == 1) ? '1 match' : c + ' matches';
			output.info("Found " + word + " for '" + string + "' in '" + dns_output.file + "'.\\n");
			output.verbose("[PROC] Found " + word + " for '" + string + "' in '" + dns_output.file + "'.\\n");
			if (c <= 20) {
				let matches = grep_output(string, dns_output.file);
				if (dns_output.parse_filter)
					matches = cmd_output(sprintf("grep %s %s | sed '%s'", shell_quote(string), shell_quote(dns_output.file), dns_output.parse_filter));
				if (matches) output.print(matches + '\\n');
			}
		} else {
			output.info("The '" + string + "' is not found in current block-list ('" + dns_output.file + "').\\n");
			output.verbose("[PROC] The '" + string + "' is not found in current block-list ('" + dns_output.file + "').\\n");
		}
	}
}

function check_tld() {
	load();
	if (!adb_file('test')) {
		output.print("No block-list ('" + dns_output.file + "') found.\\n");
		return;
	}
	let c = grep_count('\\.|server:', dns_output.file, '-cvE');
	if (c > 0) {
		let word = (c == 1) ? '1 match for TLD' : c + ' matches for TLDs';
		output.info("Found " + word + " in '" + dns_output.file + "'.\\n");
		output.verbose("[PROC] Found " + word + " in '" + dns_output.file + "'.\\n");
		if (c <= 20) {
			let matches = grep_output('\\.|server:', dns_output.file, '-vE');
			if (dns_output.parse_filter)
				matches = cmd_output(sprintf("grep -vE '\\.|server:' %s | sed '%s'", shell_quote(dns_output.file), dns_output.parse_filter));
			if (matches) output.print(matches + '\\n');
		}
	} else {
		output.info("No TLD was found in current block-list ('" + dns_output.file + "').\\n");
		output.verbose("[PROC] No TLD was found in current block-list ('" + dns_output.file + "').\\n");
	}
}

function check_leading_dot() {
	load();
	if (!adb_file('test')) {
		output.print("No block-list ('" + dns_output.file + "') found.\\n");
		return;
	}
	let search_string = '';
	switch (split(cfg.dns || '', '.')[0]) {
	case 'dnsmasq': search_string = '/\\.'; break;
	case 'smartdns': search_string = '^\\.'; break;
	case 'unbound': search_string = '"\\.'; break;
	default: return;
	}
	let c = grep_count(search_string, dns_output.file);
	if (c > 0) {
		let word = (c == 1) ? '1 match for leading-dot domain' : c + ' matches for leading-dot domains';
		output.info("Found " + word + " in '" + dns_output.file + "'.\\n");
		output.verbose("[PROC] Found " + word + " in '" + dns_output.file + "'.\\n");
		if (c <= 20) {
			let matches = grep_output(search_string, dns_output.file);
			if (dns_output.parse_filter)
				matches = cmd_output(sprintf("grep %s %s | sed '%s'", shell_quote(search_string), shell_quote(dns_output.file), dns_output.parse_filter));
			if (matches) output.print(matches + '\\n');
		}
	} else {
		output.info("No leading-dot domain was found in current block-list ('" + dns_output.file + "').\\n");
		output.verbose("[PROC] No leading-dot domain was found in current block-list ('" + dns_output.file + "').\\n");
	}
}

function check_lists(param) {
	load();
	load_dl_command();
	if (!param) {
		output.print("Usage: /etc/init.d/" + pkg.name + " check_lists 'domain' ...\\n");
		return;
	}
	uci(pkg.name).foreach(pkg.name, 'file_url', (s) => {
		if (s.enabled == '0') return;
		if ((s.action || 'block') != 'block') return;
		let url = s.url;
		let name = s.name || url;
		if (!url) return;

		output.info('Checking ' + name + ': ');
		output.verbose('[ DL ] ' + name + ' ');

		if (is_https_url(url) && !state.ssl_supported) {
			output.failn();
			return;
		}
		let r_tmp = trim(cmd_output('mktemp -q -t "' + pkg.name + '_tmp.XXXXXXXX"'));
		if (!download(url, r_tmp) || !(stat(r_tmp)?.size > 0)) {
			output.failn();
			return;
		}
		output.verbose(sym.ok[1] + '\\n');
		ensure_trailing_newline(r_tmp);

		for (let string in split('' + param, /\s+/)) {
			if (!string) continue;
			let c = grep_count(string, r_tmp, '-c -E');
			if (c > 0) {
				let word = (c == 1) ? '1 match' : c + ' matches';
				output.info("found " + word + " for '" + string + "'.\\n");
				output.verbose("[PROC] Found " + word + " for '" + string + "' in '" + url + "'.\\n");
				let matches = grep_output(string, r_tmp);
				if (matches) output.print(matches + '\\n');
			} else {
				output.info("'" + string + "' not found.\\n");
				output.verbose("[PROC] The '" + string + "' is not found in '" + url + "'.\\n");
			}
		}
		unlink(r_tmp);
	});
}

function killcache() {
	load();
	for (let mode in dns_modes) {
		let dc = dns_modes[mode];
		unlink(dc.cache);
		unlink(cfg.compressed_cache_dir + '/' + dc.gzip);
	}
	resolver('cleanup');
}

function pause_service(timeout) {
	load();
	timeout = timeout || cfg.pause_timeout || '20';
	stop();
	output.info('Sleeping for ' + timeout + ' seconds... ');
	output.verbose('[PROC] Sleeping for ' + timeout + ' seconds... ');
	if (is_integer(timeout) && system('sleep ' + timeout) == 0)
		output.okn();
	else
		output.failn();
	start(['on_pause']);
}

function show_blocklist() {
	load();
	if (dns_output.file && dns_output.parse_filter)
		system(sprintf("sed '%s' %s", dns_output.parse_filter, shell_quote(dns_output.file)));
	else if (dns_output.file)
		print(readfile(dns_output.file) || '');
}

function sizes() {
	load();
	load_dl_command();
	uci(pkg.name).foreach(pkg.name, 'file_url', (s) => {
		let size = get_url_filesize(s.url);
		output.print((s.name || s.url) + (size ? ': ' + size : '') + ' ');
		if (size) {
			uci(pkg.name).set(pkg.name, s['.name'], 'size', '' + size);
			output.okn();
		} else {
			output.failn();
		}
	});
	uci(pkg.name).save(pkg.name);
	if (cfg.update_config_sizes && length(uci(pkg.name).changes(pkg.name) || []))
		uci(pkg.name).commit(pkg.name);
}

// ── service_started_actions (called from init script) ───────────────

function service_started_actions(param) {
	load();
	status_json('load');
	if (cfg.compressed_cache && !adb_file('test_gzip') && adb_file('test')) {
		let start_time = time();
		let step_title = 'Creating ' + cfg.dns + ' compressed cache';
		output.info(step_title + ' ');
		output.verbose('[PROC] ' + step_title + ' ');
		status_data.message = get_text('statusProcessing') + ': ' + step_title;
		if (adb_file('create_gzip'))
			output.okn();
		else {
			output.failn();
			push(status_data.errors, { code: 'errorCreatingCompressedCache', info: '' });
		}
		let end_time = time();
		let elapsed = end_time - start_time;
		logger_debug('[PERF-DEBUG] ' + step_title + ' took ' + elapsed + 's');
	} else {
		adb_file('remove_gzip');
	}
	status_json('dump');
}

// ── get_network_trigger_info (for service_triggers) ─────────────────

function get_network_trigger_info() {
	load();
	let result = { procd_trigger_wan6: cfg.procd_trigger_wan6 };
	return result;
}

// ── rpcd Data Functions ─────────────────────────────────────────────

function get_init_status(name) {
	name = name || pkg.name;
	load();
	status_json('load');
	let status = status_data.status;
	let message = status_data.message;
	let stats = status_data.stats;

	// Get errors
	let errors_arr = [];
	for (let e in status_data.errors)
		push(errors_arr, { code: e.code, info: e.info });

	// Get warnings
	let warnings_arr = [];
	for (let e in status_data.warnings)
		push(warnings_arr, { code: e.code, info: e.info });

	// Service enabled/running
	let enabled = service_enabled(pkg.name);
	let running = (stat(pkg.run_file)?.size > 0);

	// Force DNS state
	let force_dns_active = false;
	let force_dns_ports = [];
	if (cfg.force_dns) {
		let ports = cfg.force_dns_port;
		if (ports) {
			force_dns_ports = split('' + ports, /[\s,]+/);
			if (length(force_dns_ports) > 0)
				force_dns_active = true;
		}
	}

	// Cache/gzip file paths and existence
	let gzip_path = cfg.compressed_cache_dir
		? cfg.compressed_cache_dir + '/' + dns_output.gzip
		: '';

	let result = {};
	result[name] = {
		version: pkg.version,
		packageCompat: int(pkg.compat),
		enabled: enabled,
		running: running,
		status: status || '',
		message: message || '',
		stats: stats || '',
		entries: int(count_blocked_domains()),
		dns: cfg.dns || '',
		outputFile: dns_output.file || '',
		outputCache: dns_output.cache || '',
		outputGzip: gzip_path,
		outputFileExists: (stat(dns_output.file)?.size > 0) || false,
		outputCacheExists: (stat(dns_output.cache)?.size > 0) || false,
		outputGzipExists: gzip_path ? (stat(gzip_path)?.size > 0) || false : false,
		force_dns_active: force_dns_active,
		force_dns_ports: force_dns_ports,
		leds: lsdir('/sys/class/leds') || [],
		errors: errors_arr,
		warnings: warnings_arr,
	};
	return result;
}

function get_init_list(name) {
	name = name || pkg.name;
	let result = {};
	let enabled_val = (uci(pkg.name).get(pkg.name, 'config', 'enabled') ?? '0');
	result[name] = { enabled: (enabled_val == '1') };
	return result;
}

function get_platform_support(name) {
	name = name || pkg.name;
	let result = {};
	result[name] = {
		ipset_installed: check_ipset(),
		nft_installed: check_nft(),
		dnsmasq_installed: is_present('dnsmasq'),
		dnsmasq_ipset_support: check_dnsmasq_ipset(),
		dnsmasq_nftset_support: check_dnsmasq_nftset(),
		smartdns_installed: is_present('smartdns'),
		smartdns_ipset_support: is_present('smartdns') && check_ipset(),
		smartdns_nftset_support: is_present('smartdns') && check_nft(),
		unbound_installed: is_present('unbound'),
		leds: length(lsdir('/sys/class/leds') || []) > 0,
	};
	return result;
}

function get_file_url_filesizes(name) {
	name = name || pkg.name;
	load();
	load_dl_command();

	let files = [];
	uci(pkg.name).foreach(pkg.name, 'file_url', (s) => {
		let size = s.size;
		if (!size && s.url) size = get_url_filesize(s.url);
		push(files, { name: s.name || s.url, url: s.url, size: size || '' });
	});

	let result = {};
	result[name] = { file_url: files };
	return result;
}

// ── Module Init & Export ────────────────────────────────────────────

function set_script_name(name) {
	state.script_name = name;
}

export default {
	init: function() {}, // backward compat (rpcd plugin may still call this)
	set_script_name,
	pkg,

	// Core lifecycle
	load,
	start,
	stop,
	status_service,

	// Config
	load_dl_command,
	load_environment,
	adb_config_update,
	adb_config_cache,

	// Extra commands
	allow,
	check,
	check_tld,
	check_leading_dot,
	check_lists,
	killcache,
	pause_service,
	show_blocklist,
	sizes,

	// rpcd data
	get_init_status,
	get_init_list,
	get_platform_support,
	get_file_url_filesizes,

	// init script helpers
	is_fw4_restart_needed,
	get_network_trigger_info,
	service_started_actions,
	emit_procd_shell,
	process_file_url,
};

