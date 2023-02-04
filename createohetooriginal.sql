use vulnerabilities;

create table one_hot_encoder_cvss30 (id int auto_increment primary key, AV_A bool, AV_L bool, AV_N bool, AV_P bool,
 AC_H bool, AC_L bool, PR_H bool, PR_L bool, PR_N bool, UI_N bool, UI_R bool,
 S_C bool, S_U	bool, I_H bool, I_L bool, I_N bool, C_H bool, C_L bool, C_N bool, A_H bool,  A_L bool,  A_N bool);
 
create table one_hot_encoder_cvss31 (id int auto_increment primary key, AV_A bool, AV_L bool, AV_N bool, AV_P bool,
 AC_H bool, AC_L bool, PR_H bool, PR_L bool, PR_N bool, UI_N bool, UI_R bool,
 S_C bool, S_U	bool, I_H bool, I_L bool, I_N bool, C_H bool, C_L bool, C_N bool, A_H bool,  A_L bool,  A_N bool);

create table one_hot_encoder_cvss20 (id int auto_increment primary key, AV_A bool, AV_L bool, AV_N bool,
 AC_H bool, AC_L bool, AC_M bool,  AU_M bool, AU_N bool, AU_S bool, I_H bool, I_L bool, I_N bool, C_C bool, C_N bool, C_P bool, A_C bool,  A_N bool,  A_P bool);