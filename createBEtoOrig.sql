use vulnerabilities;
create table BE20_to_original20(id int auto_increment primary key, BE_id int not null, original_id int not null, foreign key (BE_id) references binary_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));
create table BE30_to_original30(id int auto_increment primary key, BE_id int not null, original_id int not null, foreign key (BE_id) references binary_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));
create table BE31_to_original31(id int auto_increment primary key, BE_id int not null, original_id int not null, foreign key (BE_id) references binary_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));