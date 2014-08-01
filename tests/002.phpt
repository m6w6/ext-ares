--TEST--
ares
--SKIPIF--
<?php if (!extension_loaded("ares") || getenv("SKIP_ONLINE_TESTS")) print "skip"; ?>
--FILE--
<?php
echo "-TEST\n";

$a = ares_init();
$q = array();

foreach (array("at", "de", "uk") as $tld) {
	$q[] = ares_gethostbyname($a, null, "$tld.php.net");
}

do {
	$n = ares_fds($a, $r, $w);
	ares_select($r, $w, ares_timeout($a));
	ares_process($a, $r, $w);
} while ($n);

foreach ($q as $query) {
	print_r(ares_result($query));
}

echo "Done\n";
?>
--EXPECTF--
%sTEST
stdClass Object
(
    [name] => %s
    [aliases] => Array
        (
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            %a
        )

)
stdClass Object
(
    [name] => %s
    [aliases] => Array
        (
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            %a
        )

)
stdClass Object
(
    [name] => %s
    [aliases] => Array
        (
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            %a
        )

)
Done