<?php

//tell php to automatically flush after every output
//including lines of output produced by shell commands
function disable_ob() {
    // Turn off output buffering
    ini_set('output_buffering', 'off');
    // Turn off PHP output compression
    ini_set('zlib.output_compression', false);
    // Implicitly flush the buffer(s)
    ini_set('implicit_flush', true);
    ob_implicit_flush(true);
    // Clear, and turn off output buffering
    while (ob_get_level() > 0) {
        // Get the curent level
        $level = ob_get_level();
        // End the buffering
        ob_end_clean();
        // If the current level has not changed, abort
        if (ob_get_level() == $level) break;
    }
    // Disable apache output buffering/compression
    if (function_exists('apache_setenv')) {
        apache_setenv('no-gzip', '1');
        apache_setenv('dont-vary', '1');
    }

    //Usage:
    //disable_ob();
    //$descriptorspec = array(
    //   0 => array("pipe", "r"),   // stdin is a pipe that the child will read from
    //   1 => array("pipe", "w"),   // stdout is a pipe that the child will write to
    //   2 => array("pipe", "w")    // stderr is a pipe that the child will write to
    //);
    //flush();
    //$process = proc_open($cmd, $descriptorspec, $pipes, realpath('./'), array());
    //
    //echo "<pre>";
    //if (is_resource($process)) {
    //    while ($s = fgets($pipes[1])) {
    //        print $s;
    //        flush();
    //    }
    //}
    //echo "</pre>";
}

/**
 * Execute the given command by displaying console output live to the user.
 *  @param  string  cmd          :  command to be executed
 *  @return array   exit_status  :  exit status of the executed command
 *                  output       :  console output of the executed command
 */
function liveExecuteCommand($cmd) {
    while (@ ob_end_flush()); // end all output buffers if any

    $proc = popen("$cmd 2>&1 ; echo Exit status : $?", 'r');

    $live_output     = "";
    $complete_output = "";

    while (!feof($proc))
    {
        $live_output     = fread($proc, 4096);
        $complete_output = $complete_output . $live_output;
        echo "$live_output<br>";
        @ flush();
    }

    pclose($proc);

    // get exit status
    preg_match('/[0-9]+$/', $complete_output, $matches);

    // return exit status and intended output
    return array (
                    'exit_status'  => intval($matches[0]),
                    'output'       => str_replace("Exit status : " . $matches[0], '', $complete_output)
                 );
    //Usage:
    //$result = liveExecuteCommand("$cmd");
    //
    //if($result['exit_status'] === 0){
    //    echo "OK";
    //} else {
    //    echo "failed";
    //}
}

header("Content-type: text/html");
header('X-Accel-Buffering: no');

disable_ob();

$domain = "qmx.pp.ua";

if(isset($_GET["d"])) {
    $domain = $_GET["d"];
} else {
    echo "Hello TLS.";
    exit;
}

//Permission denied Fix:
//https://stackoverflow.com/a/8668666/992039
//chmod o+x /root /root/src /root/src/testssl.sh /root/src/testssl.sh/bin
$cmd = "/root/src/testssl.sh/testssl.sh --parallel --color 0 --quiet https://".$domain;

$descriptorspec = array(
   0 => array("pipe", "r"),   // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),   // stdout is a pipe that the child will write to
   2 => array("pipe", "w")    // stderr is a pipe that the child will write to
);
flush();
$process = proc_open($cmd, $descriptorspec, $pipes, realpath('./'), array());

echo "<pre>";
if (is_resource($process)) {
    while ($s = fgets($pipes[1])) {
        print $s;
        flush();
    }
}
echo "</pre>";

?>