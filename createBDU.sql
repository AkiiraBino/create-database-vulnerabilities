use vulnerabilities;

create table original_cvss20 (id int auto_increment primary key, class varchar(11), score decimal(2, 1),
 attack_vector char(1), access_complexity char(1), authentication char(1), confidentiality char(1), integrity char(1), availability char(1));
 
create table original_cvss30 (id int auto_increment primary key, class varchar(11),
 attack_vector char(1), access_complexity char(1), privileges_required char(1), user_interaction char(1), scope char(1),
confidentiality char(1), integrity char(1), availability char(1));

create table original_cvss31 (id int auto_increment primary key, class varchar(11), score decimal(2, 1),
 attack_vector char(1), access_complexity char(1), privileges_required char(1), user_interaction char(1), scope char(1),
confidentiality char(1), integrity char(1), availability char(1));
