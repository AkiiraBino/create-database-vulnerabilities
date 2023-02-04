use vulnerabilities;
create table label20_to_original20(id int auto_increment primary key, label_id int not null, original_id int not null, foreign key (label_id) references label_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));
create table label30_to_original30(id int auto_increment primary key, label_id int not null, original_id int not null, foreign key (label_id) references label_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));
create table label31_to_original31(id int auto_increment primary key, label_id int not null, original_id int not null, foreign key (label_id) references label_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));