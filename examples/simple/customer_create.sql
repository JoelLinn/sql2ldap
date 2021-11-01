CREATE TABLE customer (
	id serial NOT NULL,
	company varchar(60) NULL,
	surname varchar(30) NOT NULL,
	forename varchar(30) NULL,
	phone varchar(30) NULL,
	mobile varchar(30) NULL,
	email varchar(254) NULL,
	CONSTRAINT customer_pkey PRIMARY KEY (id)
);
