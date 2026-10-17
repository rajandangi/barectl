<?php
header('Content-Type: application/json');
$keys = ['opcache.enable', 'opcache.validate_permission', 'opcache.validate_root',
         'opcache.restrict_api', 'opcache.file_cache', 'opcache.preload', 'expose_php'];
$ini = [];
foreach ($keys as $key) { $ini[$key] = ini_get($key); }
$config = opcache_get_configuration();
$directives = [];
if (is_array($config)) {
    foreach ($keys as $key) {
        if (array_key_exists($key, $config['directives'])) {
            $directives[$key] = $config['directives'][$key];
        }
    }
}
$extensions = get_loaded_extensions();
sort($extensions, SORT_STRING);
echo json_encode(['version' => 1, 'sapi' => PHP_SAPI, 'php' => PHP_VERSION,
                  'parent' => posix_getppid(), 'uid' => posix_geteuid(),
                  'extensions' => $extensions, 'ini' => $ini, 'opcache' => $directives], JSON_THROW_ON_ERROR);
