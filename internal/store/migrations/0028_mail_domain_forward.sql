-- Domain forwarder (USR-MAIL-04): mail to addresses of the domain that are
-- neither a mailbox nor a forwarder goes to the same name at this domain.

ALTER TABLE mail_domains ADD COLUMN forward_to TEXT NOT NULL DEFAULT '';
