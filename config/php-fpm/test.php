<?php
/**
 * Diagnostic Script for Redis + PHP + PHP-FPM + PostgreSQL + NGINX
 * Includes timestamped debug/error messages and additional checks.
 *
 * This version:
 *   - Uses $phpversion for file paths (e.g. /etc/php/8.4/fpm/pool.d/www.conf)
 *   - Checks internal extension names ("curl", "mbstring") rather than "php8.4-curl"
 *     so that extension_loaded('curl') will work properly.
 */

// -------------------------------------------------------------------
// Adjust these variables for your environment
// -------------------------------------------------------------------
date_default_timezone_set('UTC');

$timestamp       = date('Y-m-d H:i:s');
$errors          = [];
$debugPrefix     = "[$timestamp] DEBUG: ";
$errorPrefix     = "[$timestamp] ERROR: ";

// Example dynamic variables from templates or user config
$redisUnixSocket = '{{ redis_unixsocket }}';         // Redis socket path
$pgsqlHost       = '{{ pgsql_vip }}';                // PostgreSQL host or VIP
$pgsqlUser       = '{{ pgsql_dba_name }}';           // PostgreSQL DBA username
$pgsqlPassword   = '{{ pgsql_dba_password }}';       // PostgreSQL DBA password
$pgsqlDatabase   = 'progres';                        // PostgreSQL Database
$phpversion      = '{{ php_version }}';              // e.g. "8.4"

// Construct your path dynamically
$phpFpmConfigPath = "/etc/php/$phpversion/fpm/pool.d/www.conf";

echo "[$timestamp] See below for debug...\n";

// -------------------------------------------------------------------
// Helper: Convert ini value sizes (e.g., 16M, 1G) to integer bytes
// -------------------------------------------------------------------
function parse_size($size) {
    $unit  = strtoupper(substr($size, -1));
    $value = (int) $size;
    switch ($unit) {
        case 'G':
            $value *= 1024;
            // no break
        case 'M':
            $value *= 1024;
            // no break
        case 'K':
            $value *= 1024;
            break;
    }
    return $value;
}

// -------------------------------------------------------------------
// Check internal PHP extensions (e.g. "curl" not "php8.4-curl")
// -------------------------------------------------------------------
$extensionNames = [
    'curl',
    'zip',
    'gd',
    'mbstring',
    'xml',
    'intl',
    'bz2',
    'fileinfo',
    'exif',
    'simplexml',
    'dom'
];

foreach ($extensionNames as $ext) {
    if (!extension_loaded($ext)) {
        $errors[] = "{$errorPrefix}PHP module '$ext' is not loaded.";
    } else {
        echo "{$debugPrefix}PHP extension '$ext' is loaded.\n";
    }
}


// -------------------------------------------------------------------
// Additional PHP Module Checks for Redis and PostgreSQL
// -------------------------------------------------------------------
if (extension_loaded('redis')) {
    echo "{$debugPrefix}PHP extension 'redis' is installed.\n";
} else {
    $errors[] = "{$errorPrefix}PHP extension 'redis' is not installed.";
}

if (extension_loaded('pgsql')) {
    echo "{$debugPrefix}PHP extension 'pgsql' is installed.\n";
} else {
    $errors[] = "{$errorPrefix}PHP extension 'pgsql' is not installed.";
}

// -------------------------------------------------------------------
// Check the running PHP version
// -------------------------------------------------------------------
$runningPhpVersion = phpversion();
if (version_compare($runningPhpVersion, '8.0', '<')) {
    $errors[] = "{$errorPrefix}PHP version must be 8.0 or higher. Current version: $runningPhpVersion";
} else {
    echo "{$debugPrefix}PHP version is $runningPhpVersion and is compatible.\n";
}


// -------------------------------------------------------------------
// Redis Checks (only if the user provided a real socket path)
// -------------------------------------------------------------------
$redisConfigured = extension_loaded('redis-server')
                   && file_exists($redisUnixSocket)
                   && $redisUnixSocket !== '{{ redis_unixsocket }}';

if ($redisConfigured) {
    try {
        $redis = new Redis();
        $connected = $redis->connect($redisUnixSocket);
        if (!$connected) {
            $errors[] = "{$errorPrefix}Cannot connect to Redis server at socket path: $redisUnixSocket";
            echo "{$debugPrefix}Redis connection failed at socket path: $redisUnixSocket\n";
        } else {
            $redis->ping();
            echo "{$debugPrefix}Redis connection established successfully.\n";
            
            // Redis memory usage
            try {
                $info = $redis->info();
                if (isset($info['used_memory_human'])) {
                    echo "{$debugPrefix}Redis used memory: " . $info['used_memory_human'] . "\n";
                }
            } catch (Exception $e) {
                $errors[] = "{$errorPrefix}Could not retrieve Redis info. Exception: " . $e->getMessage();
            }
        }
    } catch (Exception $e) {
        $errors[] = "{$errorPrefix}Cannot connect to Redis server. Exception: " . $e->getMessage();
    }
} else {
    echo "{$debugPrefix}Skipping Redis checks - not configured\n";
}


// -------------------------------------------------------------------
// NGINX Checks
// -------------------------------------------------------------------
$nginxStatus = shell_exec('systemctl is-active nginx 2>/dev/null');
if (trim($nginxStatus) !== 'active') {
    $errors[] = "{$errorPrefix}NGINX service is not active.";
} else {
    echo "{$debugPrefix}NGINX service is active.\n";
}

$nginxConfigTest = shell_exec('nginx -t 2>&1');
if (strpos($nginxConfigTest, 'test is successful') === false) {
    $errors[] = "{$errorPrefix}NGINX configuration test failed:\n$nginxConfigTest";
} else {
    echo "{$debugPrefix}NGINX configuration test successful.\n";
}


// -------------------------------------------------------------------
// PHP-FPM Checks
// -------------------------------------------------------------------
if (is_file($phpFpmConfigPath)) {
    $phpFpmConfig = file_get_contents($phpFpmConfigPath);
    if (strpos($phpFpmConfig, 'pm.max_children =') === false) {
        $errors[] = "{$errorPrefix}PHP-FPM configuration does not have pm.max_children set.";
    } else {
        echo "{$debugPrefix}PHP-FPM max_children configuration found.\n";
    }
} else {
    $errors[] = "{$errorPrefix}PHP-FPM configuration file not found at $phpFpmConfigPath";
}

$memoryLimit = parse_size(ini_get('memory_limit'));
if ($memoryLimit < 511 * 1024 * 1024) {
    echo "{$debugPrefix}WARNING: PHP memory_limit should be at least 512M. Current: " . ini_get('memory_limit') . "\n";
} else {
    echo "{$debugPrefix}PHP memory_limit is sufficient (" . ini_get('memory_limit') . ").\n";
}

$phpFpmStatus = shell_exec('pgrep php-fpm');
if ($phpFpmStatus === false || empty(trim($phpFpmStatus))) {
    $errors[] = "{$errorPrefix}PHP-FPM process is not running.";
    echo "{$debugPrefix}PHP-FPM process check failed.\n";
} else {
    echo "{$debugPrefix}PHP-FPM process is running.\n";
}


// -------------------------------------------------------------------
// PostgreSQL Checks (only if configured with real credentials & host)
// -------------------------------------------------------------------
$pgsqlConfigured = $pgsqlHost !== '{{ pgsql_vip }}'
                && $pgsqlUser !== '{{ pgsql_dba_name }}'
                && extension_loaded('pgsql');

if ($pgsqlConfigured) {
    echo "{$debugPrefix}Attempting to connect to PostgreSQL server at $pgsqlHost\n";
    
    $conn_string = "host=$pgsqlHost dbname=$pgsqlDatabase user=$pgsqlUser password=$pgsqlPassword";
    $pg_conn = pg_connect($conn_string);
    
    if (!$pg_conn) {
        $errors[] = "{$errorPrefix}Cannot connect to PostgreSQL server at $pgsqlHost";
        echo "{$debugPrefix}PostgreSQL connection failed at $pgsqlHost\n";
    } else {
        echo "{$debugPrefix}PostgreSQL connection established successfully.\n";
        
        // Run a test query to list tables in the public schema
        $query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';";
        $result = pg_query($pg_conn, $query);
        if (!$result) {
            $errors[] = "{$errorPrefix}Database query failed: " . pg_last_error($pg_conn);
        } else {
            echo "{$debugPrefix}Query executed successfully.\n";
            pg_free_result($result);
        }
        pg_close($pg_conn);
    }
} else {
    echo "{$debugPrefix}Skipping PostgreSQL checks - not configured\n";
}


// -------------------------------------------------------------------
// PostgreSQL Test Sequence: Create DBtest, table, insert data, verify data, drop DBtest
// Only run if PostgreSQL is configured
// -------------------------------------------------------------------
if ($pgsqlConfigured) {
    echo "{$debugPrefix}Starting PostgreSQL test sequence for database operations...\n";

    // Step 1: Connect to the default 'postgres' database for administrative tasks
    $adminConnString = "host=$pgsqlHost dbname=postgres user=$pgsqlUser password=$pgsqlPassword";
    $admin_conn = pg_connect($adminConnString);
    if (!$admin_conn) {
        $errors[] = "{$errorPrefix}Cannot connect to administrative PostgreSQL server to manage test database.";
    } else {
        // Drop test database if it exists and create a new one
        $dropDbQuery = "DROP DATABASE IF EXISTS DBtest;";
        $createDbQuery = "CREATE DATABASE DBtest;";
        
        if (!pg_query($admin_conn, $dropDbQuery)) {
           $errors[] = "{$errorPrefix}Failed to drop existing test database DBtest: " . pg_last_error($admin_conn);
        } else {
           echo "{$debugPrefix}Existing test database DBtest dropped (if existed).\n";
        }
        if (!pg_query($admin_conn, $createDbQuery)) {
           $errors[] = "{$errorPrefix}Failed to create test database DBtest: " . pg_last_error($admin_conn);
        } else {
           echo "{$debugPrefix}Test database DBtest created successfully.\n";
        }
        pg_close($admin_conn);
    }
    
    // Step 2: Connect to the newly created test database DBtest
    $testConnString = "host=$pgsqlHost dbname=DBtest user=$pgsqlUser password=$pgsqlPassword";
    $test_conn = pg_connect($testConnString);
    if (!$test_conn) {
        $errors[] = "{$errorPrefix}Cannot connect to test database DBtest.";
    } else {
        // Step 3: Create a test table with a few columns
        $createTableQuery = "CREATE TABLE test_table (
              id SERIAL PRIMARY KEY,
              name VARCHAR(50),
              value INTEGER
        );";
        if (!pg_query($test_conn, $createTableQuery)) {
           $errors[] = "{$errorPrefix}Failed to create test table: " . pg_last_error($test_conn);
        } else {
           echo "{$debugPrefix}Test table created successfully in DBtest.\n";
        }
        
        // Step 4: Insert a few rows of test data into the table
        $insertDataQuery = "INSERT INTO test_table (name, value) VALUES 
            ('Alice', 10),
            ('Bob', 20),
            ('Charlie', 30);";
        if (!pg_query($test_conn, $insertDataQuery)) {
           $errors[] = "{$errorPrefix}Failed to insert test data: " . pg_last_error($test_conn);
        } else {
           echo "{$debugPrefix}Test data inserted successfully into test table.\n";
        }
        
        // Step 5: Check if data exists in the table
        $checkDataQuery = "SELECT COUNT(*) AS count FROM test_table;";
        $result = pg_query($test_conn, $checkDataQuery);
        if (!$result) {
           $errors[] = "{$errorPrefix}Failed to check test data: " . pg_last_error($test_conn);
        } else {
           $row = pg_fetch_assoc($result);
           if ($row['count'] > 0) {
              echo "{$debugPrefix}Test data exists in test table. Count: " . $row['count'] . "\n";
           } else {
              $errors[] = "{$errorPrefix}No test data found in test table.";
           }
           pg_free_result($result);
        }
        
        pg_close($test_conn);
    }
    
    // Step 6: Reconnect to the administrative database to drop DBtest
    $admin_conn = pg_connect($adminConnString);
    if (!$admin_conn) {
        $errors[] = "{$errorPrefix}Cannot reconnect to administrative PostgreSQL server to drop test database.";
    } else {
        $dropDbQuery = "DROP DATABASE DBtest;";
        if (!pg_query($admin_conn, $dropDbQuery)) {
           $errors[] = "{$errorPrefix}Failed to drop test database DBtest: " . pg_last_error($admin_conn);
        } else {
           echo "{$debugPrefix}Test database DBtest dropped successfully.\n";
        }
        pg_close($admin_conn);
    }
} else {
    echo "{$debugPrefix}Skipping PostgreSQL test sequence - not configured\n";
}


// -------------------------------------------------------------------
// Final Summary
// -------------------------------------------------------------------
echo "\n[$timestamp] Summary:\n";

if (empty($errors)) {
    echo "{$debugPrefix}All checks passed.\n";
} else {
    foreach ($errors as $err) {
        echo $err . "\n";
    }
}
?>