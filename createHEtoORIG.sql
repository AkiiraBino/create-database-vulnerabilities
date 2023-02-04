use vulnerabilities;
create table HE20_to_original20(id int auto_increment primary key, HE_id int not null, original_id int not null, foreign key (HE_id) references helmert_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));
create table HE30_to_original30(id int auto_increment primary key, HE_id int not null, original_id int not null, foreign key (HE_id) references helmert_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));
create table HE31_to_original31(id int auto_increment primary key, HE_id int not null, original_id int not null, foreign key (HE_id) references helmert_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));