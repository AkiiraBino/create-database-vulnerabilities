use vulnerabilities;
create table TE20_to_original20(id int auto_increment primary key, target_encoder_id int not null, original_id int not null, foreign key (target_encoder_id) references target_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));
create table TE30_to_original30(id int auto_increment primary key, target_encoder_id int not null, original_id int not null, foreign key (target_encoder_id) references target_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));
create table TE31_to_original31(id int auto_increment primary key, target_encoder_id int not null, original_id int not null, foreign key (target_encoder_id) references target_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));