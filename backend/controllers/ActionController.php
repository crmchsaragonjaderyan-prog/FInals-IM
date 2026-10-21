<?php
declare(strict_types=1);
require_once __DIR__.'/../middleware/RoleMiddleware.php';
require_once __DIR__.'/../config/config.php';
function csrf_token():string{if(empty($_SESSION['csrf']))$_SESSION['csrf']=bin2hex(random_bytes(32));return $_SESSION['csrf'];}
function check_csrf():void{if(!hash_equals($_SESSION['csrf']??'',$_POST['csrf']??'')){http_response_code(419);exit('Invalid security token. Refresh the page and try again.');}}
function flash(string $type,string $message):void{$_SESSION['flash']=['type'=>$type,'message'=>$message];}
function audit(PDO $pdo,?int $uid,string $action,string $table,?int $record,string $desc):void{
 $s=$pdo->prepare("INSERT INTO audit_logs(user_id,action,table_name,record_id,description) VALUES(?,?,?,?,?)");$s->execute([$uid,$action,$table,$record,$desc]);
}
if($_SERVER['REQUEST_METHOD']!=='POST') return;
require_login($auth); check_csrf(); $action=$_POST['action']??'';
try {
 switch($action){
 case 'logout': $auth->logout(); header('Location: login.php');exit;
 case 'save_item':
   require_permission($auth,'inventory'); $id=(int)($_POST['id']??0); $name=trim($_POST['item_name']??'');$code=trim($_POST['asset_code']??'');
   $cat=(int)($_POST['category_id']??0);$brand=trim($_POST['brand']??'');$model=trim($_POST['model']??'');$serial=trim($_POST['serial_number']??'')?:null;
   $qty=max(1,(int)($_POST['quantity']??1));$cond=$_POST['condition_status']??'good';$avail=$_POST['availability_status']??'available';
   if(!$name||!$code||!$cat) throw new Exception('Item name, asset code and category are required.');
   if($id){$s=$pdo->prepare("UPDATE hardware_items SET category_id=?,asset_code=?,item_name=?,description=?,brand=?,model=?,serial_number=?,quantity=?,condition_status=?,availability_status=? WHERE id=?");$s->execute([$cat,$code,$name,trim($_POST['description']??''),$brand,$model,$serial,$qty,$cond,$avail,$id]);audit($pdo,$auth->id(),'UPDATE','hardware_items',$id,'Updated hardware item '.$code);flash('success','Hardware item updated.');}
   else{$s=$pdo->prepare("INSERT INTO hardware_items(category_id,asset_code,item_name,description,brand,model,serial_number,quantity,condition_status,availability_status) VALUES(?,?,?,?,?,?,?,?,?,?)");$s->execute([$cat,$code,$name,trim($_POST['description']??''),$brand,$model,$serial,$qty,$cond,$avail]);$nid=(int)$pdo->lastInsertId();audit($pdo,$auth->id(),'CREATE','hardware_items',$nid,'Added hardware item '.$code);flash('success','Hardware item added.');}
   break;
 case 'delete_item':
   require_permission($auth,'inventory');$id=(int)$_POST['id'];$s=$pdo->prepare("DELETE FROM hardware_items WHERE id=?");$s->execute([$id]);audit($pdo,$auth->id(),'DELETE','hardware_items',$id,'Deleted hardware item');flash('success','Hardware item deleted.');break;
 case 'save_category':
   require_permission($auth,'categories');$id=(int)($_POST['id']??0);$name=trim($_POST['name']??'');$desc=trim($_POST['description']??'');
   if(!$name)throw new Exception('Category name is required.');
   if($id){$s=$pdo->prepare("UPDATE categories SET name=?,description=? WHERE id=?");$s->execute([$name,$desc,$id]);}else{$s=$pdo->prepare("INSERT INTO categories(name,description) VALUES(?,?)");$s->execute([$name,$desc]);}
   flash('success','Category saved.');break;
 case 'save_borrower':
   require_permission($auth,'borrowers');$id=(int)($_POST['id']??0);$name=trim($_POST['borrower_name']??'');$sid=trim($_POST['student_id']??'');$email=trim($_POST['email']??'');$contact=trim($_POST['contact_number']??'');$dept=trim($_POST['department']??'');
   if(!$name)throw new Exception('Borrower name is required.');
   if($id){$pdo->prepare("UPDATE borrowers SET borrower_name=?,student_id=?,email=?,contact_number=?,department=? WHERE id=?")->execute([$name,$sid,$email,$contact,$dept,$id]);}else{$pdo->prepare("INSERT INTO borrowers(borrower_name,student_id,email,contact_number,department) VALUES(?,?,?,?,?)")->execute([$name,$sid,$email,$contact,$dept]);}
   flash('success','Borrower saved.');break;
 case 'delete_borrower':
   require_permission($auth,'borrowers');$id=(int)$_POST['id'];$pdo->prepare("DELETE FROM borrowers WHERE id=?")->execute([$id]);flash('success','Borrower deleted.');break;
 case 'mark_read':
   require_permission($auth,'notifications');$id=(int)$_POST['id'];$pdo->prepare("UPDATE notifications SET is_read=1 WHERE id=? AND (user_id IS NULL OR user_id=?)")->execute([$id,$auth->id()]);flash('success','Notification marked as read.');break;
 case 'request_loan':
   require_permission($auth,'loans'); if($auth->role()!=='student_assistant') throw new Exception('Only student assistants may submit requests.');
   $item=(int)$_POST['hardware_item_id'];$due=$_POST['due_date']?:null;$remarks=trim($_POST['remarks']??'');
   $b=$pdo->prepare("SELECT id FROM borrowers WHERE email=? LIMIT 1");$b->execute([$_SESSION['email']]);$borrower=$b->fetch();
   if(!$borrower) throw new Exception('Create your borrower profile first.');
   $i=$pdo->prepare("SELECT * FROM hardware_items WHERE id=? AND availability_status='available'");$i->execute([$item]);if(!$i->fetch())throw new Exception('Item is not available.');
   $s=$pdo->prepare("INSERT INTO loans(borrower_id,hardware_item_id,issued_by,loan_date,due_date,status,remarks) VALUES(?,?,?,CURDATE(),?,'borrowed',?)");$s->execute([$borrower['id'],$item,$auth->id(),$due,$remarks]);
   audit($pdo,$auth->id(),'CREATE','loans',(int)$pdo->lastInsertId(),'Borrow request submitted');flash('success','Borrow request recorded.');break;
 case 'return_loan':
   require_permission($auth,'loans');$id=(int)$_POST['loan_id'];$s=$pdo->prepare("UPDATE loans SET status='returned',return_date=CURDATE() WHERE id=?");$s->execute([$id]);$s=$pdo->prepare("SELECT hardware_item_id FROM loans WHERE id=?");$s->execute([$id]);$x=$s->fetch();if($x){$pdo->prepare("UPDATE hardware_items SET availability_status='available' WHERE id=?")->execute([$x['hardware_item_id']]);}audit($pdo,$auth->id(),'RETURN','loans',$id,'Equipment returned');flash('success','Loan marked as returned.');break;
 case 'update_loan':
   require_permission($auth,'loans');$id=(int)$_POST['loan_id'];$status=$_POST['status'];if(!in_array($status,['borrowed','returned','overdue'],true))throw new Exception('Invalid loan status.');
   $pdo->prepare("UPDATE loans SET status=?,return_date=IF(?='returned',CURDATE(),return_date) WHERE id=?")->execute([$status,$status,$id]);audit($pdo,$auth->id(),'UPDATE','loans',$id,'Loan status changed to '.$status);flash('success','Loan updated.');break;
 case 'update_profile':
   $name=trim($_POST['full_name']??'');$email=trim($_POST['email']??'');if(!$name||!filter_var($email,FILTER_VALIDATE_EMAIL))throw new Exception('Enter a valid name and email.');
   $s=$pdo->prepare("UPDATE users SET full_name=?,email=? WHERE id=?");$s->execute([$name,$email,$auth->id()]);$_SESSION['full_name']=$name;$_SESSION['email']=$email;flash('success','Profile updated.');break;
 case 'create_user':
   require_permission($auth,'users');$name=trim($_POST['full_name']);$email=trim($_POST['email']);$role=$_POST['role'];$pw=$_POST['password'];if(!in_array($role,ROLES,true)||strlen($pw)<6)throw new Exception('Use a valid role and password of at least 6 characters.');
   $s=$pdo->prepare("INSERT INTO users(full_name,email,password,role) VALUES(?,?,?,?)");$s->execute([$name,$email,password_hash($pw,PASSWORD_DEFAULT),$role]);audit($pdo,$auth->id(),'CREATE','users',(int)$pdo->lastInsertId(),'Created user account');flash('success','User account created.');break;
 default: throw new Exception('Unknown action.');
 }
} catch(Throwable $e){flash('danger',$e->getMessage());}
header('Location: index.php?page='.urlencode($_POST['return_page']??'dashboard'));exit;
