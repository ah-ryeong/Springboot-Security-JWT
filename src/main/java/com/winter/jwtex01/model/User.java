package com.winter.jwtex01.model;

import javax.persistence.*;

import lombok.Data;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Data
public class User {

   @Id
   @GeneratedValue(strategy = GenerationType.AUTO)
   private long id;
   private String username;
   private String password;
   private String roles;

//   public User(String username, String password, String roles, String permissions) {
//      this.username = username;
//      this.password = password;
//      this.roles = roles;
//   }

   // ENUM 사용 X → 콤마로 구분해서 ROLE 입력 후 파싱할 것!
   public List<String> getRoleList() {
      if (this.roles.length() > 0) {
         return Arrays.asList(this.roles.split(","));
      }
      return new ArrayList<>();
   }

}