--TEST--
ares
--SKIPIF--
<?php if (!extension_loaded("ares")) print "skip"; ?>
--FILE--
<?php
echo "-TEST\n";

$a = ares_init();
$q = array();

foreach (array("at", "de", "uk", "us", "ch", "ru") as $tld) {
	$q[] = ares_gethostbyname($a, null, "$tld.php.net");
}

do {
	$n = ares_fds($a, $r, $w);
	ares_select($r, $w, ares_timeout($a));
	ares_process($a, $r, $w);
} while ($n);

foreach ($q as $query) {
	print_r(ares_packet($query));
}

echo "Done\n";
?>
--EXPECTF--
%sTEST
stdClass Object
(
    [type] => 3
    [search] => 
    [query] => 
    [send] => 
    [gethostbyname] => stdClass Object
        (
            [name] => at.php.net
            [family] => 2
        )

    [gethostbyaddr] => 
    [getnameinfo] => 
)
stdClass Object
(
    [type] => 3
    [search] => 
    [query] => 
    [send] => 
    [gethostbyname] => stdClass Object
        (
            [name] => de.php.net
            [family] => 2
        )

    [gethostbyaddr] => 
    [getnameinfo] => 
)
stdClass Object
(
    [type] => 3
    [search] => 
    [query] => 
    [send] => 
    [gethostbyname] => stdClass Object
        (
            [name] => uk.php.net
            [family] => 2
        )

    [gethostbyaddr] => 
    [getnameinfo] => 
)
stdClass Object
(
    [type] => 3
    [search] => 
    [query] => 
    [send] => 
    [gethostbyname] => stdClass Object
        (
            [name] => us.php.net
            [family] => 2
        )

    [gethostbyaddr] => 
    [getnameinfo] => 
)
stdClass Object
(
    [type] => 3
    [search] => 
    [query] => 
    [send] => 
    [gethostbyname] => stdClass Object
        (
            [name] => ch.php.net
            [family] => 2
        )

    [gethostbyaddr] => 
    [getnameinfo] => 
)
stdClass Object
(
    [type] => 3
    [search] => 
    [query] => 
    [send] => 
    [gethostbyname] => stdClass Object
        (
            [name] => ru.php.net
            [family] => 2
        )

    [gethostbyaddr] => 
    [getnameinfo] => 
)
Done
