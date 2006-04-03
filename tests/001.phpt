--TEST--
ares
--SKIPIF--
<?php if (!extension_loaded("ares")) print "skip"; ?>
--FILE--
<?php 
echo "-TEST\n";

function cb()
{
	$argv = func_get_args();
	print_r($argv);
}

$a = ares_init();

ares_gethostbyname($a, "cb", "php.net");
ares_gethostbyaddr($a, "cb", "66.163.161.117");
ares_getnameinfo($a, "cb", ARES_NI_TCP, "66.163.161.117");

ares_process_all($a);
ares_destroy($a);

echo "Done\n";
?>
--EXPECTF--
%sTEST
Array
(
    [0] => Resource id #%d
    [1] => 0
    [2] => stdClass Object
        (
            [name] => php.net
            [aliases] => Array
                (
                )

            [addrtype] => 2
            [addrlist] => Array
                (
                    [0] => 66.163.161.117
                )

        )

)
Array
(
    [0] => Resource id #%d
    [1] => 0
    [2] => stdClass Object
        (
            [name] => y2.php.net
            [aliases] => Array
                (
                )

            [addrtype] => 2
            [addrlist] => Array
                (
                    [0] => 66.163.161.117
                )

        )

)
Array
(
    [0] => Resource id #%d
    [1] => 0
    [2] => y2.php.net
    [3] => 
)
Done
