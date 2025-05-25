    
<?php

date_default_timezone_set('Europe/Amsterdam');

$apcuAvailabe = function_exists('apcu_enabled') && apcu_enabled();

if($apcuAvailabe)
{
    //apcu_clear_cache();
   
    $test1 = apcu_fetch('test1');
    $test2 = apcu_fetch('test2');
}

$test1[] = rand(1, 1000);
$test2[] = rand(1, 1000);

if($apcuAvailabe)
{
    apcu_store('test1', $test1);
    apcu_store('test2', $test2);
}

echo sprintf('current - value = %s<br/>', implode(' ,', $test1));
echo sprintf('current - value = %s<br/>', implode(' ,', $test2));

$aPCUIterator = new APCUIterator();

echo sprintf('totalCount = %s<br/>', $aPCUIterator->getTotalCount());
//echo sprintf('totalHits = %s<br/>', $aPCUIterator->getTotalHits()); // Not implemneted/available?
echo sprintf('totalSize = %s<br/>', $aPCUIterator->getTotalSize());

echo '----------------------------------<br/>';

$aPCUIterator->rewind();
echo sprintf('key = %s<br/>', $aPCUIterator->key());
echoCurrent($aPCUIterator->current());
$aPCUIterator->next();

echo '----------------------------------<br/>';

echo sprintf('key = %s<br/>', $aPCUIterator->key());
echoCurrent($aPCUIterator->current());
echo sprintf('valid = %s<br/>', $aPCUIterator->valid() ? 'true' : 'false');

function echoCurrent($current)
{
   
    echo sprintf('current - type = %s<br/>', $current['type']);
    echo sprintf('current - key = %s<br/>', $current['key']);
    echo sprintf('current - value = %s<br/>', implode(' ,', $current['value']));
    //echo sprintf('current - num_hits = %s<br/>', $current['num_hits']); // Not implemneted/available?
    echo sprintf('current - mtime = %s<br/>', date("d-m-Y H:i:s", $current['mtime']));
    echo sprintf('current - creation_time = %s<br/>', date("d-m-Y H:i:s", $current['creation_time']));
    echo sprintf('current - deletion_time = %s<br/>', date("d-m-Y H:i:s", $current['deletion_time']));
    echo sprintf('current - access_time = %s<br/>', date("d-m-Y H:i:s", $current['access_time']));
    //echo sprintf('current - ref_count = %s<br/>', $current['ref_count']); // Not implemneted/available?
    echo sprintf('current - mem_size = %s<br/>', $current['mem_size']);
    //echo sprintf('current - ttl = %s<br/>', $current['ttl']); // Not implemneted/available?
}

?>

