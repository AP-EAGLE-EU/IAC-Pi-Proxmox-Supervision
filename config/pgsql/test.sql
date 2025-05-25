-- Drop the database if it exists
DROP DATABASE IF EXISTS sandbox;

-- Create the sandbox database with UTF-8 encoding and collation
CREATE DATABASE sandbox 
    WITH ENCODING='UTF8'
    LC_COLLATE='C'
    LC_CTYPE='C'
    TEMPLATE=template0;

-- Connect explicitly to the new database sandbox
\connect sandbox

-- Create the test_table with SERIAL (auto-increment) primary key
CREATE TABLE test_table (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    value INT NOT NULL
);

-- Insert data into the table
INSERT INTO test_table (name, value) VALUES
('Alice', 10),
('Bob', 20),
('successfull', 30);

-- Validate table creation and data insertion explicitly
SELECT 
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM test_table WHERE value = 30 AND name = 'successfull'
        ) 
        THEN 'TABLE_CREATION_SUCCESS' 
        ELSE 'ERROR_TABLE_CREATION_FAILED' 
    END AS table_creation_result;
