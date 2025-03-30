<?php

namespace Paperscissorsandglue\EncryptionAtRest\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use ReflectionClass;

class DecryptModelData extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'encryption:decrypt-model
                            {model : The model class to process (e.g. "App\\Models\\User")}
                            {--chunk=100 : Process records in chunks of the specified size}
                            {--dry-run : Run without making changes}
                            {--backup=true : Create a database backup before processing}
                            {--filter= : Only process records matching a where clause (e.g. "id > 100")}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Decrypt data in models using Encryptable or EncryptableJson traits';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $modelClass = $this->argument('model');
        $chunkSize = $this->option('chunk');
        $dryRun = $this->option('dry-run');
        $shouldBackup = $this->option('backup') === 'true';
        $filter = $this->option('filter');
        
        // Verify the model exists
        if (!class_exists($modelClass)) {
            $this->error("Model class {$modelClass} not found.");
            return 1;
        }
        
        // Create an instance of the model to check its traits
        $model = new $modelClass;
        $traits = $this->getTraits($model);
        
        $hasEncryptable = in_array('Paperscissorsandglue\EncryptionAtRest\Encryptable', $traits);
        $hasEncryptableJson = in_array('Paperscissorsandglue\EncryptionAtRest\EncryptableJson', $traits);
        $hasEncryptedEmail = in_array('Paperscissorsandglue\EncryptionAtRest\HasEncryptedEmail', $traits);
        
        if (!$hasEncryptable && !$hasEncryptableJson && !$hasEncryptedEmail) {
            $this->error("Model {$modelClass} does not use any encryption traits (Encryptable, EncryptableJson, or HasEncryptedEmail).");
            return 1;
        }
        
        // Check if we have fields to decrypt
        $fieldsToDecrypt = [];
        
        if ($hasEncryptable && property_exists($model, 'encryptable')) {
            $fieldsToDecrypt = array_merge($fieldsToDecrypt, $model->encryptable);
        }
        
        if ($hasEncryptableJson && property_exists($model, 'encryptableJson')) {
            $this->info("Found JSON fields to decrypt: " . implode(', ', array_keys($model->encryptableJson)));
        }
        
        if ($hasEncryptedEmail) {
            $this->info("Found HasEncryptedEmail trait. Will decrypt email (email_index will be preserved).");
        }
        
        if (empty($fieldsToDecrypt) && !$hasEncryptableJson && !$hasEncryptedEmail) {
            $this->error("No fields to decrypt found in the model.");
            return 1;
        }
        
        if ($hasEncryptable) {
            $this->info("Found fields to decrypt: " . implode(', ', $fieldsToDecrypt));
        }
        
        // Show security warning
        $this->warn("WARNING: Decryption of data is irreversible and removes privacy protection. This should only be used");
        $this->warn("         in specific situations or when migrating away from the encryption system.");
        
        if (!$this->confirm('Do you understand the security implications of decrypting data?', false)) {
            $this->info('Operation cancelled by user.');
            return 0;
        }
        
        // Backup confirmation
        if ($shouldBackup) {
            if ($this->confirm('This will create a database backup before processing. Continue?', true)) {
                $this->backup();
            } else {
                if (!$this->confirm('Proceeding without backup. Are you sure you want to continue?', false)) {
                    $this->info('Operation cancelled by user.');
                    return 0;
                }
            }
        }
        
        // Show what's about to happen
        $this->info("Processing model: {$modelClass}");
        $this->info("Chunk size: {$chunkSize}");
        if ($filter) {
            $this->info("Filter: {$filter}");
        }
        if ($dryRun) {
            $this->info("DRY RUN: No changes will be made to the database.");
        }
        
        if (!$this->confirm('Ready to begin decryption. Continue?', false)) {
            $this->info('Operation cancelled by user.');
            return 0;
        }
        
        // Process in chunks
        $count = 0;
        $query = $modelClass::query();
        
        // Apply filter if provided
        if ($filter) {
            $query->whereRaw($filter);
        }
        
        $total = $query->count();
        $this->info("Found {$total} records to process.");
        
        if ($total === 0) {
            $this->info("No records to process. Exiting.");
            return 0;
        }
        
        $bar = $this->output->createProgressBar($total);
        $bar->start();
        
        // Process normal fields and JSON fields
        $query->chunk($chunkSize, function ($records) use (&$count, $dryRun, $hasEncryptable, $hasEncryptableJson, $hasEncryptedEmail, $bar) {
            foreach ($records as $record) {
                if (!$dryRun) {
                    DB::beginTransaction();
                    try {
                        // Find all encrypted fields and manually decrypt them
                        $this->decryptRecord($record, $hasEncryptable, $hasEncryptableJson, $hasEncryptedEmail);
                        $record->save();
                        DB::commit();
                        $count++;
                    } catch (\Exception $e) {
                        DB::rollBack();
                        $this->error("Error processing ID {$record->id}: " . $e->getMessage());
                    }
                } else {
                    $count++;
                }
                
                $bar->advance();
            }
        });
        
        $bar->finish();
        $this->newLine();
        
        if ($dryRun) {
            $this->info("Dry run completed. {$count} records would be processed.");
        } else {
            $this->info("Decryption completed. {$count} records updated.");
        }
        
        return 0;
    }
    
    /**
     * Decrypt a single record's fields directly.
     *
     * @param Model $record
     * @param bool $hasEncryptable
     * @param bool $hasEncryptableJson 
     * @param bool $hasEncryptedEmail
     */
    protected function decryptRecord($record, $hasEncryptable, $hasEncryptableJson, $hasEncryptedEmail)
    {
        // Get the encryption service
        $encryptionService = app(\Paperscissorsandglue\EncryptionAtRest\EncryptionService::class);
        
        // Process regular fields
        if ($hasEncryptable && property_exists($record, 'encryptable')) {
            foreach ($record->encryptable as $field) {
                if (isset($record->attributes[$field]) && !empty($record->attributes[$field])) {
                    try {
                        // Try to decrypt the field
                        $decrypted = $encryptionService->decrypt($record->attributes[$field]);
                        $record->attributes[$field] = $decrypted;
                    } catch (\Exception $e) {
                        // Field may already be decrypted, leave it as is
                    }
                }
            }
        }
        
        // Process email separately
        if ($hasEncryptedEmail && isset($record->attributes['email']) && !empty($record->attributes['email'])) {
            try {
                // Try to decrypt the email
                $decrypted = $encryptionService->decrypt($record->attributes['email']);
                $record->attributes['email'] = $decrypted;
                // Note: we're keeping the email_index for searchability
            } catch (\Exception $e) {
                // Email may already be decrypted, leave it as is
            }
        }
        
        // Process JSON fields
        if ($hasEncryptableJson && property_exists($record, 'encryptableJson')) {
            foreach ($record->encryptableJson as $jsonField => $encryptedKeys) {
                if (isset($record->attributes[$jsonField]) && !empty($record->attributes[$jsonField])) {
                    $json = json_decode($record->attributes[$jsonField], true) ?: [];
                    $modified = false;
                    
                    foreach ($encryptedKeys as $key) {
                        if (isset($json[$key]) && !empty($json[$key])) {
                            try {
                                // Try to decrypt the field
                                $decrypted = $encryptionService->decrypt($json[$key]);
                                $json[$key] = $decrypted;
                                $modified = true;
                            } catch (\Exception $e) {
                                // Field may already be decrypted, leave it as is
                            }
                        }
                    }
                    
                    if ($modified) {
                        $record->attributes[$jsonField] = json_encode($json);
                    }
                }
            }
        }
    }
    
    /**
     * Get all traits used by a model and its parent classes.
     *
     * @param  Model  $model
     * @return array
     */
    protected function getTraits($model)
    {
        $traits = [];
        $class = get_class($model);
        
        do {
            $traits = array_merge($traits, class_uses($class));
            $class = get_parent_class($class);
        } while ($class);
        
        // Get traits of traits
        foreach ($traits as $trait) {
            $traits = array_merge($traits, class_uses($trait));
        }
        
        return array_unique($traits);
    }
    
    /**
     * Create a database backup.
     */
    protected function backup()
    {
        $connection = config('database.default');
        $driver = config("database.connections.{$connection}.driver");
        
        if ($driver === 'mysql') {
            $this->info('Creating MySQL backup...');
            
            $db = config("database.connections.{$connection}.database");
            $user = config("database.connections.{$connection}.username");
            $password = config("database.connections.{$connection}.password");
            $host = config("database.connections.{$connection}.host");
            
            $backupPath = storage_path('app/backups');
            if (!file_exists($backupPath)) {
                mkdir($backupPath, 0755, true);
            }
            
            $filename = $backupPath . '/' . $db . '-' . date('Y-m-d-H-i-s') . '.sql';
            
            $command = "mysqldump --user={$user} --password={$password} --host={$host} {$db} > {$filename}";
            exec($command, $output, $returnVar);
            
            if ($returnVar === 0) {
                $this->info("Database backup created at {$filename}");
            } else {
                $this->error("Database backup failed. Continue with caution.");
                if (!$this->confirm('Proceed without backup?', false)) {
                    $this->info('Operation cancelled by user.');
                    exit;
                }
            }
        } else {
            $this->warn("Automatic backup not supported for {$driver} database. Please backup your database manually before proceeding.");
            if (!$this->confirm('Continue without backup?', false)) {
                $this->info('Operation cancelled by user.');
                exit;
            }
        }
    }
}