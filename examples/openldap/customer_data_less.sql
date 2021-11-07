DELETE FROM customer WHERE id IN (SELECT id FROM customer WHERE NOT phone <> '' OR NOT mobile <> '' OFFSET 50)
