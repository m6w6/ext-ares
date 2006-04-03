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
	print_r(ares_result($query));
}

echo "Done\n";
?>
--EXPECTF--
%sTEST
stdClass Object
(
    [name] => gd.tuwien.ac.at
    [aliases] => Array
        (
            [0] => at.php.net
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            [0] => 192.35.244.50
        )

)
stdClass Object
(
    [name] => php3.globe.de
    [aliases] => Array
        (
            [0] => de.php.net
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            [0] => 212.124.37.9
        )

)
stdClass Object
(
    [name] => php.networkedsystems.co.uk
    [aliases] => Array
        (
            [0] => uk.php.net
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            [0] => 85.116.4.7
        )

)
stdClass Object
(
    [name] => ch.php.net
    [aliases] => Array
        (
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            [0] => 128.178.77.24
        )

)
stdClass Object
(
    [name] => php.directnet.ru
    [aliases] => Array
        (
            [0] => ru.php.net
        )

    [addrtype] => 2
    [addrlist] => Array
        (
            [0] => 195.222.164.18
        )

)
Done