--TEST--
ares
--SKIPIF--
<?php if (!extension_loaded("ares") || getenv("SKIP_ONLINE_TESTS")) print "skip"; ?>
--FILE--
<?php 
echo "-TEST\n";

function cb()
{
	$argv = func_get_args();
	print_r($argv);
}

$a = ares_init();

ares_gethostbyname($a, "cb", "a.resolvers.Level3.net");
ares_gethostbyaddr($a, "cb", "4.2.2.2");
ares_getnameinfo($a, "cb", ARES_NI_TCP, "4.2.2.3");

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
            [name] => a.resolvers.Level3.net
            [aliases] => Array
                (
                )

            [addrtype] => 2
            [addrlist] => Array
                (
                    [0] => 4.2.2.1
                )

        )

)
Array
(
    [0] => Resource id #%d
    [1] => 0
    [2] => stdClass Object
        (
            [name] => b.resolvers.Level3.net
            [aliases] => Array
                (
                    [0] => b.resolvers.Level3.net
                )

            [addrtype] => 2
            [addrlist] => Array
                (
                    [0] => 4.2.2.2
                )

        )

)
Array
(
    [0] => Resource id #%d
    [1] => 0
    [2] => c.resolvers.level3.net
    [3] => 
)
Done
