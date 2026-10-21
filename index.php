<?php
declare(strict_types=1);

/*
 * IT Laboratory Asset Tracking System
 * Single-entry index.php
 *
 * Role UI:
 *  staff              = full administration
 *  student_assistant  = inventory + borrowers + loans/returns
 *  instructor         = inventory/search + own/issued loans + reports
 *
 * This version does not require backend/bootstrap.php or ActionController.php.
 * It works directly with the schema used by the project:
 * users, categories, hardware_items, borrowers, loans, notifications, audit_logs.
 */

session_start();
date_default_timezone_set('Asia/Manila');

const DB_HOST = 'sql104.byetcluster.com';
const DB_NAME = 'if0_43162353_it_lab_asset_tracking';
const DB_USER = 'if0_43162353';
const DB_PASS = 'AX1fL2I6WU';
const APP_NAME = 'IT Laboratory Asset Tracking System';

function e(mixed $v): string { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function go(string $url): never { header('Location: '.$url); exit; }
function roleLabel(string $role): string { return match($role) {
    'staff' => 'Staff', 'student_assistant' => 'Student Assistant', 'instructor' => 'Instructor', default => ucfirst(str_replace('_',' ',$role))
}; }
function csrf(): string { if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function csrfField(): string { return '<input type="hidden" name="csrf" value="'.e(csrf()).'">'; }
function verifyCsrf(): void { if(!hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) { http_response_code(419); exit('Invalid security token. Please refresh and try again.'); } }
function fmtDate(?string $d, string $format='M d, Y'): string { if(!$d) return '—'; $t=strtotime($d); return $t ? date($format,$t) : '—'; }
function badge(string $status): string { $c=match($status){'available','returned','good','read'=>'success','borrowed','fair'=>'warning','overdue','damaged','unavailable'=>'danger','maintenance'=>'info',default=>'secondary'}; return '<span class="badge-soft badge-'.$c.'">'.e(ucfirst(str_replace('_',' ',$status))).'</span>'; }
function flash(?string $type=null, ?string $message=null): ?array { if($message!==null){$_SESSION['flash']=['type'=>$type,'message'=>$message]; return null;} $x=$_SESSION['flash']??null; unset($_SESSION['flash']); return $x; }
function hasRole(string ...$roles): bool { return in_array($_SESSION['role'] ?? '', $roles, true); }
function can(string $permission): bool { $role=$_SESSION['role']??''; return match($permission) {
    'inventory_manage' => in_array($role,['staff','student_assistant'],true),
    'categories' => $role==='staff',
    'borrowers' => in_array($role,['staff','student_assistant'],true),
    'loans_manage' => in_array($role,['staff','student_assistant'],true),
    'reports_all' => $role==='staff',
    'reports_self' => in_array($role,['instructor'],true),
    'users' => $role==='staff',
    'audit' => $role==='staff',
    'notifications' => in_array($role,['staff','student_assistant','instructor'],true),
    default => false,
}; }
function requirePage(string $page): void {
    $role=$_SESSION['role']??'';
    $allowed=[
      'dashboard'=>['staff','student_assistant','instructor'],
      'inventory'=>['staff','student_assistant','instructor'],
      'categories'=>['staff'],
      'borrowers'=>['staff','student_assistant'],
      'loans'=>['staff','student_assistant','instructor'],
      'transactions'=>['staff','student_assistant'],
      'reports'=>['staff','instructor'],
      'notifications'=>['staff','student_assistant','instructor'],
      'users'=>['staff'],
      'audit'=>['staff'],
      'profile'=>['staff','student_assistant','instructor'],
      'export'=>['staff','instructor'],
    ];
    if(!isset($allowed[$page]) || !in_array($role,$allowed[$page],true)){ http_response_code(403); exit('<h1>403 Forbidden</h1><p>Your role is not allowed to open this page.</p><p><a href="index.php?page=dashboard">Back to dashboard</a></p>'); }
}

try {
    $pdo=new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',DB_USER,DB_PASS,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);
} catch(Throwable $ex) {
    http_response_code(500); exit('<h1>Database connection failed</h1><p>'.e($ex->getMessage()).'</p>');
}

/* Login/logout are handled here so an older Auth.php cannot break the login page. */
if(($_GET['action']??'')==='logout'){
    $_SESSION=[]; if(ini_get('session.use_cookies')){ $p=session_get_cookie_params(); setcookie(session_name(),' ',time()-42000,$p['path'],$p['domain'],$p['secure'],$p['httponly']); }
    session_destroy(); go('index.php?page=login');
}

if(empty($_SESSION['user_id'])){
    $loginError='';
    $signupError='';
    $signupSuccess='';

    /* -------------------- SIGN UP --------------------
     * Public registration is limited to student assistants and instructors.
     * Staff accounts should be created by an existing staff administrator.
     */
    if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='signup'){
        verifyCsrf();

        $fullName=trim((string)($_POST['full_name']??''));
        $email=strtolower(trim((string)($_POST['email']??'')));
        $password=(string)($_POST['password']??'');
        $confirm=(string)($_POST['confirm_password']??'');
        $newRole=(string)($_POST['role']??'');

        if($fullName==='' || mb_strlen($fullName)<2){
            $signupError='Please enter your full name.';
        } elseif(!filter_var($email,FILTER_VALIDATE_EMAIL)){
            $signupError='Please enter a valid email address.';
        } elseif(strlen($password)<6){
            $signupError='Password must be at least 6 characters.';
        } elseif($password!==$confirm){
            $signupError='Passwords do not match.';
        } elseif(!in_array($newRole,['student_assistant','instructor'],true)){
            $signupError='Please select a valid account role.';
        } else {
            $st=$pdo->prepare('SELECT id FROM users WHERE email=? LIMIT 1');
            $st->execute([$email]);
            if($st->fetch()){
                $signupError='An account with this email already exists. Please log in instead.';
            } else {
                try {
                    $hash=password_hash($password,PASSWORD_DEFAULT);
                    $st=$pdo->prepare('INSERT INTO users(full_name,email,password,role) VALUES(?,?,?,?)');
                    $st->execute([$fullName,$email,$hash,$newRole]);
                    $signupSuccess='Account created successfully. You can now log in.';
                } catch(PDOException $ex){
                    if((string)$ex->errorInfo[1]==='1062'){
                        $signupError='An account with this email already exists.';
                    } else {
                        $signupError='Unable to create the account right now. Please try again.';
                    }
                }
            }
        }
    }

    /* -------------------- LOGIN -------------------- */
    if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='login'){
        verifyCsrf();
        $email=trim((string)($_POST['email']??''));
        $password=(string)($_POST['password']??'');
        $st=$pdo->prepare('SELECT * FROM users WHERE email=? LIMIT 1');
        $st->execute([$email]);
        $u=$st->fetch();
        $valid=$u && in_array($u['role'],['staff','student_assistant','instructor'],true) &&
            (password_verify($password,(string)$u['password']) || hash_equals((string)$u['password'],$password));
        if($valid){
            if(!password_verify($password,(string)$u['password'])){
                $new=password_hash($password,PASSWORD_DEFAULT);
                $pdo->prepare('UPDATE users SET password=? WHERE id=?')->execute([$new,$u['id']]);
            }
            session_regenerate_id(true);
            $_SESSION['user_id']=(int)$u['id'];
            $_SESSION['full_name']=$u['full_name'];
            $_SESSION['email']=$u['email'];
            $_SESSION['role']=$u['role'];
            $_SESSION['csrf']=bin2hex(random_bytes(32));
            go('index.php?page=dashboard');
        }
        $loginError='Invalid email/password. Please check your credentials.';
    }

    /* -------------------- LOGIN / SIGN UP UI -------------------- */
    $showSignup=(($_GET['page']??'login')==='signup');
    ?><!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title><?=e($showSignup?'Sign Up · '.APP_NAME:APP_NAME)?></title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            body{min-height:100vh;background:#f3f6fb;display:grid;place-items:center;padding:24px}
            .auth-wrap{width:min(460px,96vw)}
            .brand{font-weight:800;color:#183b70}
            .card{border:0;border-radius:20px;box-shadow:0 12px 35px #00000012}
            .form-control,.form-select{border-radius:11px;padding:.75rem .9rem}
            .btn{border-radius:11px}
            .small-link{text-decoration:none}
        </style>
    </head>
    <body>
    <div class="auth-wrap">
        <div class="text-center mb-4">
            <div class="brand fs-3"><i class="bi bi-pc-display-horizontal me-2"></i>IT Laboratory</div>
            <div class="text-muted">Asset Tracking System</div>
        </div>

        <div class="card p-4">
            <?php if($showSignup): ?>
                <h4 class="mb-1">Create an account</h4>
                <p class="text-muted mb-4">Register as a Student Assistant or Instructor.</p>

                <?php if($signupError): ?><div class="alert alert-danger"><?=e($signupError)?></div><?php endif; ?>
                <?php if($signupSuccess): ?><div class="alert alert-success"><?=e($signupSuccess)?></div><?php endif; ?>

                <form method="post" novalidate>
                    <?=csrfField()?>
                    <input type="hidden" name="action" value="signup">

                    <div class="mb-3">
                        <label class="form-label">Full Name</label>
                        <input class="form-control" type="text" name="full_name" value="<?=e($_POST['full_name']??'')?>" autocomplete="name" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input class="form-control" type="email" name="email" value="<?=e($_POST['email']??'')?>" autocomplete="email" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Role</label>
                        <select class="form-select" name="role" required>
                            <option value="">Select role</option>
                            <option value="student_assistant" <?=((($_POST['role']??'')==='student_assistant')?'selected':'')?>>Student Assistant</option>
                            <option value="instructor" <?=((($_POST['role']??'')==='instructor')?'selected':'')?>>Instructor</option>
                        </select>
                        <div class="form-text">Staff accounts are created by Staff administrators.</div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input class="form-control" type="password" name="password" autocomplete="new-password" minlength="6" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Confirm Password</label>
                        <input class="form-control" type="password" name="confirm_password" autocomplete="new-password" minlength="6" required>
                    </div>

                    <button class="btn btn-primary btn-lg w-100" type="submit">
                        <i class="bi bi-person-plus me-1"></i>Create Account
                    </button>
                </form>

                <div class="text-center mt-3">
                    <span class="text-muted">Already have an account?</span>
                    <a class="small-link" href="index.php?page=login">Sign in</a>
                </div>
            <?php else: ?>
                <h4 class="mb-1">Sign in</h4>
                <p class="text-muted mb-4">Log in using your registered account.</p>

                <?php if($loginError): ?><div class="alert alert-danger"><?=e($loginError)?></div><?php endif; ?>

                <form method="post">
                    <?=csrfField()?>
                    <input type="hidden" name="action" value="login">
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input class="form-control form-control-lg" type="email" name="email" value="<?=e($_POST['email']??'')?>" autocomplete="email" required autofocus>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input class="form-control form-control-lg" type="password" name="password" autocomplete="current-password" required>
                    </div>
                    <button class="btn btn-primary btn-lg w-100" type="submit">
                        <i class="bi bi-box-arrow-in-right me-1"></i>Login
                    </button>
                </form>

                <div class="text-center mt-3">
                    <span class="text-muted">Don't have an account?</span>
                    <a class="small-link" href="index.php?page=signup">Sign up</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
    </body>
    </html><?php exit;
}

$uid=(int)$_SESSION['user_id']; $role=(string)$_SESSION['role'];
$meSt=$pdo->prepare('SELECT * FROM users WHERE id=? LIMIT 1'); $meSt->execute([$uid]); $me=$meSt->fetch();
if(!$me){ session_destroy(); go('index.php?page=login'); }

/* Keep loan statuses current. */
$pdo->exec("UPDATE loans SET status='overdue' WHERE status='borrowed' AND due_date IS NOT NULL AND due_date < CURDATE()");

$page=$_GET['page']??'dashboard';
if($page==='login') $page='dashboard';
requirePage($page);

/* -------------------- ACTIONS -------------------- */
if($_SERVER['REQUEST_METHOD']==='POST'){
    verifyCsrf();
    $action=(string)($_POST['action']??'');
    try {
        switch($action){
            case 'create_item':
                if(!can('inventory_manage')) throw new RuntimeException('You cannot manage inventory.');
                $name=trim((string)$_POST['item_name']); $asset=trim((string)$_POST['asset_code']); $cat=(int)$_POST['category_id'];
                $q=max(1,(int)($_POST['quantity']??1)); $cond=(string)($_POST['condition_status']??'good'); $avail=(string)($_POST['availability_status']??'available');
                $st=$pdo->prepare('INSERT INTO hardware_items(category_id,asset_code,item_name,description,brand,model,serial_number,quantity,condition_status,availability_status) VALUES(?,?,?,?,?,?,?,?,?,?)');
                $st->execute([$cat,$asset,$name,trim((string)$_POST['description']),trim((string)$_POST['brand']),trim((string)$_POST['model']),trim((string)$_POST['serial_number'])?:null,$q,$cond,$avail]);
                $id=(int)$pdo->lastInsertId(); audit($pdo,$uid,'CREATE','hardware_items',$id,'Created hardware asset '.$asset); flash('success','Asset added successfully.'); go('index.php?page=inventory');
            case 'update_item':
                if(!can('inventory_manage')) throw new RuntimeException('You cannot manage inventory.');
                $id=(int)$_POST['id']; $st=$pdo->prepare('UPDATE hardware_items SET category_id=?,asset_code=?,item_name=?,description=?,brand=?,model=?,serial_number=?,quantity=?,condition_status=?,availability_status=? WHERE id=?');
                $st->execute([(int)$_POST['category_id'],trim((string)$_POST['asset_code']),trim((string)$_POST['item_name']),trim((string)$_POST['description']),trim((string)$_POST['brand']),trim((string)$_POST['model']),trim((string)$_POST['serial_number'])?:null,max(1,(int)$_POST['quantity']),$_POST['condition_status'],$_POST['availability_status'],$id]);
                audit($pdo,$uid,'UPDATE','hardware_items',$id,'Updated hardware asset'); flash('success','Asset updated.'); go('index.php?page=inventory');
            case 'delete_item':
                if(!can('inventory_manage')) throw new RuntimeException('You cannot manage inventory.');
                $id=(int)$_POST['id']; $chk=$pdo->prepare("SELECT COUNT(*) FROM loans WHERE hardware_item_id=? AND status IN ('borrowed','overdue')"); $chk->execute([$id]); if((int)$chk->fetchColumn()>0) throw new RuntimeException('Cannot delete an asset with an active loan.');
                $pdo->prepare('DELETE FROM hardware_items WHERE id=?')->execute([$id]); audit($pdo,$uid,'DELETE','hardware_items',$id,'Deleted hardware asset'); flash('success','Asset deleted.'); go('index.php?page=inventory');
            case 'create_category':
                if(!can('categories')) throw new RuntimeException('Staff only.'); $st=$pdo->prepare('INSERT INTO categories(name,description) VALUES(?,?)'); $st->execute([trim((string)$_POST['name']),trim((string)$_POST['description'])]); $id=(int)$pdo->lastInsertId(); audit($pdo,$uid,'CREATE','categories',$id,'Created category'); flash('success','Category created.'); go('index.php?page=categories');
            case 'update_category':
                if(!can('categories')) throw new RuntimeException('Staff only.'); $id=(int)$_POST['id']; $pdo->prepare('UPDATE categories SET name=?,description=? WHERE id=?')->execute([trim((string)$_POST['name']),trim((string)$_POST['description']),$id]); audit($pdo,$uid,'UPDATE','categories',$id,'Updated category'); flash('success','Category updated.'); go('index.php?page=categories');
            case 'delete_category':
                if(!can('categories')) throw new RuntimeException('Staff only.'); $id=(int)$_POST['id']; $chk=$pdo->prepare('SELECT COUNT(*) FROM hardware_items WHERE category_id=?');$chk->execute([$id]);if((int)$chk->fetchColumn()>0)throw new RuntimeException('Category is being used by hardware assets.');$pdo->prepare('DELETE FROM categories WHERE id=?')->execute([$id]);audit($pdo,$uid,'DELETE','categories',$id,'Deleted category');flash('success','Category deleted.');go('index.php?page=categories');
            case 'create_borrower':
                if(!can('borrowers')) throw new RuntimeException('You cannot manage borrowers.'); $st=$pdo->prepare('INSERT INTO borrowers(borrower_name,student_id,email,contact_number,department) VALUES(?,?,?,?,?)');$st->execute([trim((string)$_POST['borrower_name']),trim((string)$_POST['student_id']),trim((string)$_POST['email']),trim((string)$_POST['contact_number']),trim((string)$_POST['department'])]);$id=(int)$pdo->lastInsertId();audit($pdo,$uid,'CREATE','borrowers',$id,'Created borrower');flash('success','Borrower added.');go('index.php?page=borrowers');
            case 'update_borrower':
                if(!can('borrowers')) throw new RuntimeException('You cannot manage borrowers.');$id=(int)$_POST['id'];$pdo->prepare('UPDATE borrowers SET borrower_name=?,student_id=?,email=?,contact_number=?,department=? WHERE id=?')->execute([trim((string)$_POST['borrower_name']),trim((string)$_POST['student_id']),trim((string)$_POST['email']),trim((string)$_POST['contact_number']),trim((string)$_POST['department']),$id]);audit($pdo,$uid,'UPDATE','borrowers',$id,'Updated borrower');flash('success','Borrower updated.');go('index.php?page=borrowers');
            case 'delete_borrower':
                if(!can('borrowers')) throw new RuntimeException('You cannot manage borrowers.');$id=(int)$_POST['id'];$chk=$pdo->prepare('SELECT COUNT(*) FROM loans WHERE borrower_id=?');$chk->execute([$id]);if((int)$chk->fetchColumn()>0)throw new RuntimeException('Borrower has loan history and cannot be deleted.');$pdo->prepare('DELETE FROM borrowers WHERE id=?')->execute([$id]);audit($pdo,$uid,'DELETE','borrowers',$id,'Deleted borrower');flash('success','Borrower deleted.');go('index.php?page=borrowers');
            case 'tx_issue_loan':
                if(!hasRole('staff','student_assistant')) throw new RuntimeException('Only Staff and Student Assistants can issue equipment.');
                $bid=(int)($_POST['borrower_id']??0);$iid=(int)($_POST['hardware_item_id']??0);$due=(string)($_POST['due_date']??'');$remarks=trim((string)($_POST['remarks']??''));
                if($bid<1||$iid<1||$due===''||$due<date('Y-m-d'))throw new RuntimeException('Choose a borrower, available asset, and valid due date.');
                $pdo->beginTransaction();
                $st=$pdo->prepare('SELECT id,item_name,asset_code,availability_status FROM hardware_items WHERE id=? FOR UPDATE');$st->execute([$iid]);$item=$st->fetch();
                if(!$item||$item['availability_status']!=='available')throw new RuntimeException('Asset is no longer available. Transaction cancelled.');
                $st=$pdo->prepare('SELECT id FROM borrowers WHERE id=?');$st->execute([$bid]);if(!$st->fetch())throw new RuntimeException('Borrower does not exist.');
                $st=$pdo->prepare("INSERT INTO loans(borrower_id,hardware_item_id,issued_by,loan_date,due_date,status,remarks) VALUES(?,?,?,?,?,'borrowed',?)");$st->execute([$bid,$iid,$uid,date('Y-m-d'),$due,$remarks]);$lid=(int)$pdo->lastInsertId();
                $st=$pdo->prepare("UPDATE hardware_items SET availability_status='borrowed' WHERE id=? AND availability_status='available'");$st->execute([$iid]);if($st->rowCount()!==1)throw new RuntimeException('Asset availability changed; transaction cancelled.');
                audit($pdo,$uid,'CREATE','loans',$lid,'TCL demo: issued '.$item['asset_code'].' to borrower #'.$bid.'; loan and asset status committed atomically.');
                $pdo->commit();flash('success','COMMIT successful: loan created and asset marked borrowed.');go('index.php?page=transactions');
            case 'tx_return_loan':
                if(!hasRole('staff','student_assistant')) throw new RuntimeException('Only Staff and Student Assistants can process returns.');
                $lid=(int)($_POST['loan_id']??0);if($lid<1)throw new RuntimeException('Invalid loan ID.');
                $pdo->beginTransaction();$st=$pdo->prepare('SELECT id,hardware_item_id,status FROM loans WHERE id=? FOR UPDATE');$st->execute([$lid]);$loan=$st->fetch();
                if(!$loan||!in_array($loan['status'],['borrowed','overdue'],true))throw new RuntimeException('Active loan not found; nothing was changed.');
                $st=$pdo->prepare("UPDATE loans SET status='returned',return_date=? WHERE id=?");$st->execute([date('Y-m-d'),$lid]);
                $st=$pdo->prepare("UPDATE hardware_items SET availability_status='available' WHERE id=?");$st->execute([(int)$loan['hardware_item_id']]);
                audit($pdo,$uid,'RETURN','loans',$lid,'TCL demo: return processed; loan and asset availability committed atomically.');$pdo->commit();flash('success','COMMIT successful: loan marked returned and asset made available.');go('index.php?page=transactions');
            case 'issue_loan':
                if(!can('loans_manage')) throw new RuntimeException('This role cannot issue loans.');
                $bid=(int)$_POST['borrower_id'];$iid=(int)$_POST['hardware_item_id'];
                $st=$pdo->prepare("SELECT * FROM hardware_items WHERE id=? LIMIT 1");$st->execute([$iid]);$item=$st->fetch();if(!$item || $item['availability_status']!=='available')throw new RuntimeException('Selected asset is not available.');
                $st=$pdo->prepare('INSERT INTO loans(borrower_id,hardware_item_id,issued_by,loan_date,due_date,status,remarks) VALUES(?,?,?,?,?,?,?)');$st->execute([$bid,$iid,$uid,date('Y-m-d'),$_POST['due_date']?:null,'borrowed',trim((string)$_POST['remarks'])]);$lid=(int)$pdo->lastInsertId();$pdo->prepare("UPDATE hardware_items SET availability_status='borrowed' WHERE id=?")->execute([$iid]);
                $users=$pdo->query("SELECT id FROM users WHERE role IN ('staff','student_assistant')")->fetchAll();foreach($users as $u){$pdo->prepare('INSERT INTO notifications(user_id,loan_id,title,message,type,is_read) VALUES(?,?,?,?,?,0)')->execute([$u['id'],$lid,'New equipment loan','An equipment loan was issued for '.($item['item_name']??'an asset').'.','system']);}
                audit($pdo,$uid,'CREATE','loans',$lid,'Issued equipment loan');flash('success','Loan issued successfully.');go('index.php?page=loans');
            case 'return_loan':
                if(!can('loans_manage')) throw new RuntimeException('This role cannot process returns.');$id=(int)$_POST['id'];$st=$pdo->prepare('SELECT * FROM loans WHERE id=? LIMIT 1');$st->execute([$id]);$loan=$st->fetch();if(!$loan)throw new RuntimeException('Loan not found.');$pdo->prepare("UPDATE loans SET return_date=?,status='returned',remarks=? WHERE id=?")->execute([date('Y-m-d'),trim((string)$_POST['remarks']),$id]);$pdo->prepare("UPDATE hardware_items SET availability_status='available' WHERE id=?")->execute([(int)$loan['hardware_item_id']]);audit($pdo,$uid,'UPDATE','loans',$id,'Returned equipment');flash('success','Equipment returned successfully.');go('index.php?page=loans');
            case 'mark_notification':
                if(!can('notifications')) throw new RuntimeException('Not allowed.');$id=(int)$_POST['id'];$pdo->prepare('UPDATE notifications SET is_read=1 WHERE id=? AND (user_id=? OR user_id IS NULL)')->execute([$id,$uid]);go('index.php?page=notifications');
            case 'create_user':
                if(!can('users')) throw new RuntimeException('Staff only.');$roleNew=(string)$_POST['role'];if(!in_array($roleNew,['staff','student_assistant','instructor'],true))throw new RuntimeException('Invalid role.');$hash=password_hash((string)$_POST['password'],PASSWORD_DEFAULT);$st=$pdo->prepare('INSERT INTO users(full_name,email,password,role) VALUES(?,?,?,?)');$st->execute([trim((string)$_POST['full_name']),trim((string)$_POST['email']),$hash,$roleNew]);$id=(int)$pdo->lastInsertId();audit($pdo,$uid,'CREATE','users',$id,'Created '.$roleNew.' account');flash('success','User account created.');go('index.php?page=users');
            case 'delete_user':
                if(!can('users')) throw new RuntimeException('Staff only.');$id=(int)$_POST['id'];if($id===$uid)throw new RuntimeException('You cannot delete your own account.');$pdo->prepare('DELETE FROM users WHERE id=?')->execute([$id]);audit($pdo,$uid,'DELETE','users',$id,'Deleted user account');flash('success','User deleted.');go('index.php?page=users');
            case 'save_profile':
                $name=trim((string)$_POST['full_name']);$email=trim((string)$_POST['email']);$pdo->prepare('UPDATE users SET full_name=?,email=? WHERE id=?')->execute([$name,$email,$uid]);if(trim((string)$_POST['password'])!=='')$pdo->prepare('UPDATE users SET password=? WHERE id=?')->execute([password_hash((string)$_POST['password'],PASSWORD_DEFAULT),$uid]);$_SESSION['full_name']=$name;$_SESSION['email']=$email;audit($pdo,$uid,'UPDATE','users',$uid,'Updated own profile');flash('success','Profile updated.');go('index.php?page=profile');
        }
    } catch(Throwable $ex) { if(isset($pdo) && $pdo->inTransaction()) $pdo->rollBack(); flash('danger',$ex->getMessage()); go('index.php?page='.urlencode(in_array($_POST['action']??'', ['tx_issue_loan','tx_return_loan'], true)?'transactions':$page)); }
}

function audit(PDO $pdo,int $user,string $action,string $table,?int $record,string $description): void { $st=$pdo->prepare('INSERT INTO audit_logs(user_id,action,table_name,record_id,description) VALUES(?,?,?,?,?)');$st->execute([$user,$action,$table,$record,$description]); }

/* -------------------- EXPORT -------------------- */
if($page==='export'){
    $from=$_GET['from']??'';$to=$_GET['to']??'';$where=[];$params=[];if($from!==''){$where[]='l.loan_date>=?';$params[]=$from;}if($to!==''){$where[]='l.loan_date<=?';$params[]=$to;}if($role==='instructor'){$where[]='l.issued_by=?';$params[]=$uid;}$sql="SELECT l.id,b.student_id,b.borrower_name,h.item_name,h.serial_number,l.loan_date,l.due_date,l.return_date,l.status FROM loans l JOIN borrowers b ON b.id=l.borrower_id JOIN hardware_items h ON h.id=l.hardware_item_id".($where?' WHERE '.implode(' AND ',$where):'')." ORDER BY l.loan_date DESC";$st=$pdo->prepare($sql);$st->execute($params);header('Content-Type:text/csv; charset=utf-8');header('Content-Disposition:attachment; filename=it_lab_borrowing_report_'.date('Ymd_His').'.csv');$out=fopen('php://output','w');fputcsv($out,['Loan ID','Student ID','Borrower','Asset','Serial Number','Borrow Date','Due Date','Return Date','Status']);while($r=$st->fetch())fputcsv($out,$r);fclose($out);exit;
}

/* -------------------- DATA FOR PAGES -------------------- */
$title=match($page){'transactions'=>'Transaction Demo — Inventory TCL','loans'=>'Loans & Returns','inventory'=>'Hardware Inventory','borrowers'=>'Borrower Management','reports'=>'Borrowing Reports','notifications'=>'Notifications','users'=>'User Accounts','audit'=>'Activity Audit Logs','profile'=>'My Profile',default=>roleLabel($role).' Dashboard'};
$flash=flash();
$categories=$pdo->query('SELECT * FROM categories ORDER BY name')->fetchAll();
$counts=$pdo->query("SELECT COUNT(*) total,SUM(availability_status='available') available,SUM(availability_status='borrowed') borrowed,SUM(availability_status='maintenance') maintenance FROM hardware_items")->fetch() ?: ['total'=>0,'available'=>0,'borrowed'=>0,'maintenance'=>0];

/* -------------------- HTML -------------------- */
?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=e($title).' · '.e(APP_NAME)?></title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet"><style>
:root{--nav:#102f57;--nav2:#16477f;--bg:#f4f7fb;--line:#e6ebf2;--text:#182230}.body{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif}.sidebar{position:fixed;inset:0 auto 0 0;width:255px;background:linear-gradient(180deg,var(--nav),#0b2444);color:#fff;z-index:1030;transition:.25s}.sidebar.collapsed{width:76px}.brand{height:74px;padding:20px 18px;font-weight:800;border-bottom:1px solid #ffffff18;white-space:nowrap;overflow:hidden}.brand i{font-size:24px}.nav-link{color:#dbe7f7;border-radius:10px;margin:3px 12px;padding:11px 13px;display:flex;gap:12px;align-items:center;white-space:nowrap}.nav-link:hover,.nav-link.active{background:#ffffff18;color:#fff}.nav-link i{font-size:18px;min-width:22px;text-align:center}.sidebar.collapsed .nav-link span,.sidebar.collapsed .brand span,.sidebar.collapsed .rolebox{display:none}.main{margin-left:255px;min-height:100vh;transition:.25s}.main.expanded{margin-left:76px}.topbar{height:74px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:1000}.content{padding:24px}.cardx{background:#fff;border:1px solid var(--line);border-radius:15px;box-shadow:0 4px 15px #1c31500b}.stat{padding:18px}.label{font-size:11px;letter-spacing:.08em;color:#718096;font-weight:700}.value{font-size:30px;font-weight:800;margin-top:7px}.metric-icon{width:40px;height:40px;border-radius:11px;background:#edf4ff;color:#1d5fae;display:grid;place-items:center}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:18px;flex-wrap:wrap}.table-card{overflow:hidden}.table{margin:0}.table th{font-size:12px;text-transform:uppercase;color:#718096;letter-spacing:.04em;background:#fbfcfe}.table td,.table th{padding:13px 14px;vertical-align:middle}.badge-soft{display:inline-block;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:700}.badge-success{background:#e6f7ed;color:#18733e}.badge-warning{background:#fff4d6;color:#8a6100}.badge-danger{background:#ffe7e7;color:#a32323}.badge-info{background:#e3f3fb;color:#17607d}.badge-secondary{background:#edf0f4;color:#596575}.empty{padding:35px;text-align:center;color:#7b8796}.hero{background:linear-gradient(135deg,#153e70,#2465a6);color:#fff;border-radius:17px;padding:25px}.quick{display:block;padding:15px;text-decoration:none;color:inherit;height:100%}.quick i{font-size:22px;color:#1e63aa}.avatar{width:50px;height:50px;border-radius:50%;display:grid;place-items:center;background:#eaf2ff;color:#1c5ba0;font-weight:800}.rolebox{padding:12px 18px;color:#bcd0e8;font-size:12px}.form-control,.form-select{border-color:#dce3ec}.btn-primary{background:#185ca8;border-color:#185ca8}.searchbox{min-width:min(650px,100%)}.mobile-menu{display:none}@media(max-width:900px){.sidebar{width:76px}.sidebar .nav-link span,.sidebar .brand span,.sidebar .rolebox{display:none}.main{margin-left:76px}.mobile-menu{display:inline-block}.content{padding:15px}}
</style></head><body>
<aside class="sidebar" id="sidebar"><div class="brand"><i class="bi bi-pc-display-horizontal me-2"></i><span>IT LAB TRACKER</span></div><div class="rolebox"><div>Logged in as</div><strong><?=e(roleLabel($role))?></strong></div><nav class="mt-2">
<a class="nav-link <?=$page==='dashboard'?'active':''?>" href="index.php?page=dashboard"><i class="bi bi-grid-1x2"></i><span>Dashboard</span></a>
<a class="nav-link <?=$page==='inventory'?'active':''?>" href="index.php?page=inventory"><i class="bi bi-box-seam"></i><span>Inventory</span></a>
<?php if(can('categories')):?><a class="nav-link <?=$page==='categories'?'active':''?>" href="index.php?page=categories"><i class="bi bi-tags"></i><span>Categories</span></a><?php endif;?>
<?php if(can('borrowers')):?><a class="nav-link <?=$page==='borrowers'?'active':''?>" href="index.php?page=borrowers"><i class="bi bi-people"></i><span>Borrowers</span></a><?php endif;?>
<a class="nav-link <?=$page==='loans'?'active':''?>" href="index.php?page=loans"><i class="bi bi-arrow-left-right"></i><span><?=hasRole('instructor')?'My Loans':'Loans & Returns'?></span></a>
<?php if(hasRole('staff','student_assistant')):?><a class="nav-link <?=$page==='transactions'?'active':''?>" href="index.php?page=transactions"><i class="bi bi-arrow-repeat"></i><span>Transaction Demo</span></a><?php endif;?>
<?php if(hasRole('staff','instructor')):?><a class="nav-link <?=$page==='reports'?'active':''?>" href="index.php?page=reports"><i class="bi bi-bar-chart"></i><span><?=hasRole('instructor')?'My Reports':'Reports'?></span></a><?php endif;?>
<a class="nav-link <?=$page==='notifications'?'active':''?>" href="index.php?page=notifications"><i class="bi bi-bell"></i><span>Notifications</span></a>
<?php if(can('users')):?><a class="nav-link <?=$page==='users'?'active':''?>" href="index.php?page=users"><i class="bi bi-person-gear"></i><span>User Accounts</span></a><?php endif;?>
<?php if(can('audit')):?><a class="nav-link <?=$page==='audit'?'active':''?>" href="index.php?page=audit"><i class="bi bi-shield-check"></i><span>Audit Logs</span></a><?php endif;?>
<a class="nav-link <?=$page==='profile'?'active':''?>" href="index.php?page=profile"><i class="bi bi-person-circle"></i><span>My Profile</span></a>
</nav></aside>
<main class="main" id="main"><header class="topbar"><div><button class="btn btn-light me-2" id="toggle"><i class="bi bi-list"></i></button><strong><?=e($title)?></strong></div><div class="d-flex align-items-center gap-3"><div class="text-end d-none d-sm-block"><b><?=e($me['full_name'])?></b><small class="d-block text-muted"><?=e(roleLabel($role))?></small></div><div class="avatar"><?=e(strtoupper(substr($me['full_name'],0,1)))?></div><a class="btn btn-outline-danger btn-sm" href="index.php?action=logout" title="Logout"><i class="bi bi-box-arrow-right"></i></a></div></header><section class="content">
<?php if($flash):?><div class="alert alert-<?=e($flash['type'])?> alert-dismissible fade show"><?=e($flash['message'])?><button class="btn-close" data-bs-dismiss="alert"></button></div><?php endif;?>
<?php
switch($page):
case 'dashboard':
    $scope=$role==='staff'?null:$uid;
    $sql='SELECT COUNT(*) FROM loans WHERE status IN (\'borrowed\',\'overdue\')';$p=[];if($scope!==null){$sql.=' AND issued_by=?';$p[]=$scope;}$st=$pdo->prepare($sql);$st->execute($p);$active=(int)$st->fetchColumn();
    $sql='SELECT COUNT(*) FROM loans WHERE status=\'overdue\'';$p=[];if($scope!==null){$sql.=' AND issued_by=?';$p[]=$scope;}$st=$pdo->prepare($sql);$st->execute($p);$overdue=(int)$st->fetchColumn();
    $sql="SELECT l.*,b.borrower_name,b.student_id,h.item_name FROM loans l JOIN borrowers b ON b.id=l.borrower_id JOIN hardware_items h ON h.id=l.hardware_item_id";if($scope!==null){$sql.=' WHERE l.issued_by=?';}$sql.=' ORDER BY l.created_at DESC LIMIT 6';$st=$pdo->prepare($sql);$st->execute($scope===null?[]:[$scope]);$recent=$st->fetchAll();
    ?><div class="hero mb-4"><div class="row align-items-center"><div class="col-lg-8"><h2>Welcome, <?=e($me['full_name'])?>.</h2><p class="mb-0"><?php if($role==='staff'):?>You have full control over assets, users, borrowers, loans, reports, notifications, and audit logs.<?php elseif($role==='student_assistant'):?>Manage laboratory equipment, borrowers, borrowing transactions, and returns.<?php else:?>Search equipment and review loans and reports issued by your account.<?php endif;?></p></div><div class="col-lg-4 text-lg-end mt-3 mt-lg-0"><a class="btn btn-light" href="index.php?page=inventory"><i class="bi bi-search me-1"></i>Search Inventory</a></div></div></div><div class="row g-3 mb-4"><div class="col-sm-6 col-xl-3"><div class="cardx stat"><span class="label">TOTAL ASSETS</span><div class="value"><?=e($counts['total']??0)?></div></div></div><div class="col-sm-6 col-xl-3"><div class="cardx stat"><span class="label">AVAILABLE</span><div class="value"><?=e($counts['available']??0)?></div></div></div><div class="col-sm-6 col-xl-3"><div class="cardx stat"><span class="label"><?=hasRole('staff')?'ACTIVE LOANS':'MY ACTIVE LOANS'?></span><div class="value"><?=e($active)?></div></div></div><div class="col-sm-6 col-xl-3"><div class="cardx stat"><span class="label">OVERDUE</span><div class="value"><?=e($overdue)?></div></div></div></div><div class="row g-3"><div class="col-lg-4"><div class="cardx p-3"><h6>Role functions</h6><ul class="list-group list-group-flush"><li class="list-group-item px-0">Inventory: <?=can('inventory_manage')?'Manage':'View/Search only'?></li><li class="list-group-item px-0">Borrowers: <?=can('borrowers')?'Manage':'No management access'?></li><li class="list-group-item px-0">Loans: <?=can('loans_manage')?'Issue & Return':'View own/issued records'?></li><li class="list-group-item px-0">Reports: <?=hasRole('staff')?'All':'Own issued records'?></li><li class="list-group-item px-0">Accounts/Audit: <?=hasRole('staff')?'Full':'No access'?></li></ul></div></div><div class="col-lg-8"><div class="cardx table-card"><div class="p-3 d-flex justify-content-between"><h6 class="mb-0">Recent loan activity</h6><a href="index.php?page=loans">View all</a></div><div class="table-responsive"><table class="table"><thead><tr><th>Borrower</th><th>Asset</th><th>Due</th><th>Status</th></tr></thead><tbody><?php foreach($recent as $r):?><tr><td><?=e($r['borrower_name'])?><small class="d-block text-muted"><?=e($r['student_id'])?></small></td><td><?=e($r['item_name'])?></td><td><?=fmtDate($r['due_date'])?></td><td><?=badge($r['status'])?></td></tr><?php endforeach;if(!$recent):?><tr><td colspan="4" class="empty">No loan records yet.</td></tr><?php endif;?></tbody></table></div></div></div></div><?php break;
case 'inventory':
    $search=trim((string)($_GET['search']??''));$status=(string)($_GET['status']??'');$cat=(int)($_GET['category']??0);$where=[];$params=[];if($search!==''){$where[]='(h.asset_code LIKE ? OR h.item_name LIKE ? OR h.brand LIKE ? OR h.model LIKE ? OR h.serial_number LIKE ?)';for($i=0;$i<5;$i++)$params[]='%'.$search.'%';}if($status!==''){$where[]='h.availability_status=?';$params[]=$status;}if($cat){$where[]='h.category_id=?';$params[]=$cat;}$sql='SELECT h.*,c.name category_name FROM hardware_items h JOIN categories c ON c.id=h.category_id'.($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY h.item_name';$st=$pdo->prepare($sql);$st->execute($params);$items=$st->fetchAll();
    ?><div class="toolbar"><form class="d-flex gap-2 searchbox" method="get"><input type="hidden" name="page" value="inventory"><input class="form-control" name="search" value="<?=e($search)?>" placeholder="Search asset code, name, brand, serial..."><select class="form-select" name="status" style="max-width:160px"><option value="">All status</option><?php foreach(['available','borrowed','maintenance','unavailable'] as $s):?><option value="<?=$s?>" <?=$status===$s?'selected':''?>><?=ucfirst($s)?></option><?php endforeach;?></select><select class="form-select" name="category" style="max-width:180px"><option value="0">All categories</option><?php foreach($categories as $c):?><option value="<?=$c['id']?>" <?=$cat==(int)$c['id']?'selected':''?>><?=e($c['name'])?></option><?php endforeach;?></select><button class="btn btn-outline-primary"><i class="bi bi-search"></i></button></form><?php if(can('inventory_manage')):?><button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#itemModal"><i class="bi bi-plus-lg me-1"></i>Add Asset</button><?php endif;?></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Asset</th><th>Category</th><th>Serial</th><th>Qty</th><th>Status</th><th>Condition</th><?php if(can('inventory_manage')):?><th>Actions</th><?php endif;?></tr></thead><tbody><?php foreach($items as $i):?><tr><td><b><?=e($i['item_name'])?></b><small class="d-block text-muted"><?=e($i['asset_code'])?></small></td><td><?=e($i['category_name'])?></td><td><?=e($i['serial_number']??'—')?></td><td><?=e($i['quantity'])?></td><td><?=badge($i['availability_status'])?></td><td><?=badge($i['condition_status'])?></td><?php if(can('inventory_manage')):?><td><button class="btn btn-sm btn-outline-primary" onclick='editItem(<?=json_encode($i,JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)?>)'><i class="bi bi-pencil"></i></button><form class="d-inline" method="post" onsubmit="return confirm('Delete this asset?')"><?=csrfField()?><input type="hidden" name="action" value="delete_item"><input type="hidden" name="id" value="<?=$i['id']?>"><button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button></form></td><?php endif;?></tr><?php endforeach;if(!$items):?><tr><td colspan="7" class="empty">No assets found.</td></tr><?php endif;?></tbody></table></div></div><?php if(can('inventory_manage')):?><?php require __DIR__ . '/modals/asset_modal.php'; ?><?php endif; break;
case 'categories':
    $rows=$pdo->query('SELECT c.*,COUNT(h.id) item_count FROM categories c LEFT JOIN hardware_items h ON h.category_id=c.id GROUP BY c.id ORDER BY c.name')->fetchAll();?><div class="toolbar"><div><h5 class="mb-0">Categories</h5><small class="text-muted">Staff-only category administration.</small></div><button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#catModal"><i class="bi bi-plus-lg me-1"></i>Add Category</button></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Name</th><th>Description</th><th>Assets</th><th>Actions</th></tr></thead><tbody><?php foreach($rows as $r):?><tr><td><b><?=e($r['name'])?></b></td><td><?=e($r['description'])?></td><td><?=e($r['item_count'])?></td><td><button class="btn btn-sm btn-outline-primary" onclick='editCat(<?=json_encode($r,JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)?>)'><i class="bi bi-pencil"></i></button> <form class="d-inline" method="post" onsubmit="return confirm('Delete category?')"><?=csrfField()?><input type="hidden" name="action" value="delete_category"><input type="hidden" name="id" value="<?=$r['id']?>"><button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button></form></td></tr><?php endforeach;?></tbody></table></div></div><?php require __DIR__ . '/modals/category_modal.php'; ?><?php break;
case 'borrowers':
    $search=trim((string)($_GET['search']??''));$sql='SELECT * FROM borrowers';$params=[];if($search!==''){$sql.=' WHERE borrower_name LIKE ? OR student_id LIKE ? OR email LIKE ?';$params=['%'.$search.'%','%'.$search.'%','%'.$search.'%'];}$sql.=' ORDER BY borrower_name';$st=$pdo->prepare($sql);$st->execute($params);$rows=$st->fetchAll();?><div class="toolbar"><form class="d-flex gap-2 searchbox" method="get"><input type="hidden" name="page" value="borrowers"><input class="form-control" name="search" value="<?=e($search)?>" placeholder="Search borrower or student ID"><button class="btn btn-outline-primary"><i class="bi bi-search"></i></button></form><button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#borrowerModal"><i class="bi bi-person-plus me-1"></i>Add Borrower</button></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Borrower</th><th>Student ID</th><th>Email</th><th>Contact</th><th>Department</th><th>Actions</th></tr></thead><tbody><?php foreach($rows as $r):?><tr><td><b><?=e($r['borrower_name'])?></b></td><td><?=e($r['student_id'])?></td><td><?=e($r['email'])?></td><td><?=e($r['contact_number'])?></td><td><?=e($r['department'])?></td><td><button class="btn btn-sm btn-outline-primary" onclick='editBorrower(<?=json_encode($r,JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)?>)'><i class="bi bi-pencil"></i></button><form class="d-inline" method="post" onsubmit="return confirm('Delete borrower?')"><?=csrfField()?><input type="hidden" name="action" value="delete_borrower"><input type="hidden" name="id" value="<?=$r['id']?>"><button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button></form></td></tr><?php endforeach;if(!$rows):?><tr><td colspan="6" class="empty">No borrowers found.</td></tr><?php endif;?></tbody></table></div></div><?php require __DIR__ . '/modals/borrower_modal.php'; ?><?php break;
case 'transactions':
    if(!hasRole('staff','student_assistant')){http_response_code(403);echo '<div class="alert alert-danger">Only Staff and Student Assistants can run inventory transactions.</div>';break;}
    $items=$pdo->query("SELECT id,asset_code,item_name,availability_status FROM hardware_items ORDER BY item_name")->fetchAll();
    $borrowers=$pdo->query("SELECT id,borrower_name,student_id FROM borrowers ORDER BY borrower_name")->fetchAll();
    $txRows=$pdo->query("SELECT l.id,l.loan_date,l.due_date,l.return_date,l.status,l.remarks,b.borrower_name,b.student_id,h.item_name,h.asset_code,u.full_name AS operator FROM loans l JOIN borrowers b ON b.id=l.borrower_id JOIN hardware_items h ON h.id=l.hardware_item_id JOIN users u ON u.id=l.issued_by ORDER BY l.id DESC LIMIT 100")->fetchAll();
    ?><div class="toolbar"><div><h5 class="mb-1">Transaction Control — Inventory Loans</h5><small class="text-muted">Demonstrates database transactions (COMMIT / ROLLBACK) using real assets, borrowers, and loan records.</small></div></div>
    <div class="row g-3 mb-4"><div class="col-lg-7"><div class="cardx p-4 h-100"><h6 class="mb-3">Issue Equipment (Atomic Transaction)</h6><p class="text-muted small">The loan record and asset availability update are committed together. If either operation fails, both are rolled back.</p><form method="post"><?=csrfField()?><input type="hidden" name="action" value="tx_issue_loan"><div class="mb-3"><label class="form-label">Borrower</label><select class="form-select" name="borrower_id" required><option value="">Select borrower</option><?php foreach($borrowers as $b):?><option value="<?=$b['id']?>"><?=e($b['borrower_name'])?><?= $b['student_id']?' — '.e($b['student_id']):'' ?></option><?php endforeach;?></select></div><div class="mb-3"><label class="form-label">Available asset</label><select class="form-select" name="hardware_item_id" required><option value="">Select available asset</option><?php foreach($items as $i):if($i['availability_status']==='available'):?><option value="<?=$i['id']?>"><?=e($i['item_name'])?> (<?=e($i['asset_code'])?>)</option><?php endif;endforeach;?></select></div><div class="mb-3"><label class="form-label">Due date</label><input class="form-control" type="date" name="due_date" min="<?=date('Y-m-d')?>" required></div><div class="mb-3"><label class="form-label">Remarks</label><textarea class="form-control" name="remarks" rows="2"></textarea></div><button class="btn btn-primary"><i class="bi bi-check2-circle me-1"></i>Run Issue Transaction</button></form></div></div>
    <div class="col-lg-5"><div class="cardx p-4 h-100"><h6>How TCL applies here</h6><ol class="small mb-0"><li class="mb-2"><b>BEGIN TRANSACTION</b> — start a unit of work.</li><li class="mb-2"><b>SELECT … FOR UPDATE</b> — lock the asset row to avoid double issue.</li><li class="mb-2"><b>INSERT loan + UPDATE asset</b> — keep related records consistent.</li><li class="mb-2"><b>COMMIT</b> — save both changes together.</li><li><b>ROLLBACK</b> — cancel all changes if validation or a query fails.</li></ol><hr><p class="small text-muted mb-0">This demo does not use unrelated bank balances. It works directly with your IT Lab Tracking System database tables.</p></div></div></div>
    <div class="cardx table-card"><div class="p-3 border-bottom"><b>Recent Inventory Transactions</b><small class="text-muted d-block">Latest 100 loan and return records</small></div><div class="table-responsive"><table class="table"><thead><tr><th>ID</th><th>Borrower</th><th>Asset</th><th>Operator</th><th>Loan date</th><th>Due date</th><th>Status</th><th>Return action</th></tr></thead><tbody><?php foreach($txRows as $r):?><tr><td>#<?=$r['id']?></td><td><?=e($r['borrower_name'])?><small class="d-block text-muted"><?=e($r['student_id'])?></small></td><td><?=e($r['item_name'])?><small class="d-block text-muted"><?=e($r['asset_code'])?></small></td><td><?=e($r['operator'])?></td><td><?=fmtDate($r['loan_date'])?></td><td><?=fmtDate($r['due_date'])?></td><td><?=badge($r['status'])?></td><td><?php if(in_array($r['status'],['borrowed','overdue'],true)):?><form method="post" onsubmit="return confirm('Return this asset using an atomic transaction?')"><?=csrfField()?><input type="hidden" name="action" value="tx_return_loan"><input type="hidden" name="loan_id" value="<?=$r['id']?>"><button class="btn btn-sm btn-success">Return / Commit</button></form><?php else:?><span class="text-muted">Completed <?=fmtDate($r['return_date'])?></span><?php endif;?></td></tr><?php endforeach;if(!$txRows):?><tr><td colspan="8" class="empty">No transaction records yet.</td></tr><?php endif;?></tbody></table></div></div><?php break;
case 'loans':
    $where=[];$params=[];if($role==='instructor'){$where[]='l.issued_by=?';$params[]=$uid;}if(($q=trim((string)($_GET['search']??'')))!==''){$where[]='(b.borrower_name LIKE ? OR b.student_id LIKE ? OR h.item_name LIKE ? OR h.asset_code LIKE ?)';for($i=0;$i<4;$i++)$params[]='%'.$q.'%';}$sql='SELECT l.*,b.borrower_name,b.student_id,h.item_name,h.asset_code,u.full_name issuer FROM loans l JOIN borrowers b ON b.id=l.borrower_id JOIN hardware_items h ON h.id=l.hardware_item_id JOIN users u ON u.id=l.issued_by'.($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY l.created_at DESC';$st=$pdo->prepare($sql);$st->execute($params);$rows=$st->fetchAll();$borrowers=$pdo->query('SELECT * FROM borrowers ORDER BY borrower_name')->fetchAll();$available=$pdo->query("SELECT id,asset_code,item_name,serial_number FROM hardware_items WHERE availability_status='available' ORDER BY item_name")->fetchAll();?><div class="toolbar"><form class="d-flex gap-2 searchbox" method="get"><input type="hidden" name="page" value="loans"><input class="form-control" name="search" value="<?=e($_GET['search']??'')?>" placeholder="Search loan, borrower, student ID, asset"><button class="btn btn-outline-primary"><i class="bi bi-search"></i></button></form><?php if(can('loans_manage')):?><button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#loanModal"><i class="bi bi-box-arrow-right me-1"></i>Issue Loan</button><?php endif;?></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Borrower</th><th>Asset</th><th>Issued By</th><th>Loan Date</th><th>Due</th><th>Status</th><?php if(can('loans_manage')):?><th>Action</th><?php endif;?></tr></thead><tbody><?php foreach($rows as $r):?><tr><td><b><?=e($r['borrower_name'])?></b><small class="d-block text-muted"><?=e($r['student_id'])?></small></td><td><?=e($r['item_name'])?><small class="d-block text-muted"><?=e($r['asset_code'])?></small></td><td><?=e($r['issuer'])?></td><td><?=fmtDate($r['loan_date'])?></td><td><?=fmtDate($r['due_date'])?></td><td><?=badge($r['status'])?></td><?php if(can('loans_manage')):?><td><?php if(in_array($r['status'],['borrowed','overdue'],true)):?><form method="post" onsubmit="return confirm('Mark this equipment as returned?')"><?=csrfField()?><input type="hidden" name="action" value="return_loan"><input type="hidden" name="id" value="<?=$r['id']?>"><button class="btn btn-sm btn-success">Return</button></form><?php else:?><span class="text-muted">Returned <?=fmtDate($r['return_date'])?></span><?php endif;?></td><?php endif;?></tr><?php endforeach;if(!$rows):?><tr><td colspan="7" class="empty">No loan records found.</td></tr><?php endif;?></tbody></table></div></div><?php if(can('loans_manage')):?><?php require __DIR__ . '/modals/loan_modal.php'; ?><?php endif; break;
case 'reports':
    $from=$_GET['from']??'';$to=$_GET['to']??'';$where=[];$params=[];if($from!==''){$where[]='l.loan_date>=?';$params[]=$from;}if($to!==''){$where[]='l.loan_date<=?';$params[]=$to;}if($role==='instructor'){$where[]='l.issued_by=?';$params[]=$uid;}$sql='SELECT l.*,b.borrower_name,b.student_id,h.item_name,h.serial_number FROM loans l JOIN borrowers b ON b.id=l.borrower_id JOIN hardware_items h ON h.id=l.hardware_item_id'.($where?' WHERE '.implode(' AND ',$where):'').' ORDER BY l.loan_date DESC';$st=$pdo->prepare($sql);$st->execute($params);$rows=$st->fetchAll();?><div class="cardx p-3 mb-3"><form class="row g-2 align-items-end"><input type="hidden" name="page" value="reports"><div class="col-md-4"><label class="form-label">From</label><input class="form-control" type="date" name="from" value="<?=e($from)?>"></div><div class="col-md-4"><label class="form-label">To</label><input class="form-control" type="date" name="to" value="<?=e($to)?>"></div><div class="col-md-4 d-flex gap-2"><button class="btn btn-primary">Filter</button><a class="btn btn-outline-secondary" href="index.php?page=export&from=<?=urlencode($from)?>&to=<?=urlencode($to)?>">Export CSV</a></div></form></div><div class="row g-3 mb-3"><div class="col-md-4"><div class="cardx stat"><span class="label">TRANSACTIONS</span><div class="value"><?=count($rows)?></div></div></div><div class="col-md-4"><div class="cardx stat"><span class="label">ACTIVE / OVERDUE</span><div class="value"><?=count(array_filter($rows,fn($r)=>in_array($r['status'],['borrowed','overdue'],true)))?></div></div></div><div class="col-md-4"><div class="cardx stat"><span class="label">RETURNED</span><div class="value"><?=count(array_filter($rows,fn($r)=>$r['status']==='returned'))?></div></div></div></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Date</th><th>Borrower</th><th>Asset</th><th>Due</th><th>Return</th><th>Status</th></tr></thead><tbody><?php foreach($rows as $r):?><tr><td><?=fmtDate($r['loan_date'])?></td><td><?=e($r['borrower_name'])?></td><td><?=e($r['item_name'])?></td><td><?=fmtDate($r['due_date'])?></td><td><?=fmtDate($r['return_date'])?></td><td><?=badge($r['status'])?></td></tr><?php endforeach;?></tbody></table></div></div><?php break;
case 'notifications':
    $st=$pdo->prepare('SELECT n.*,l.hardware_item_id,h.item_name FROM notifications n LEFT JOIN loans l ON l.id=n.loan_id LEFT JOIN hardware_items h ON h.id=l.hardware_item_id WHERE n.user_id=? OR n.user_id IS NULL ORDER BY n.created_at DESC');$st->execute([$uid]);$rows=$st->fetchAll();?><div class="toolbar"><div><h5 class="mb-0">Notifications</h5><small class="text-muted">Return reminders, overdue alerts, and system activity.</small></div></div><div class="row g-3"><?php foreach($rows as $n):?><div class="col-lg-6"><div class="cardx p-3"><div class="d-flex justify-content-between"><b><?=e($n['title'])?></b><small class="text-muted"><?=fmtDate($n['created_at'],'M d, Y h:i A')?></small></div><p class="my-2"><?=e($n['message'])?></p><?php if(!$n['is_read']):?><form method="post"><?=csrfField()?><input type="hidden" name="action" value="mark_notification"><input type="hidden" name="id" value="<?=$n['id']?>"><button class="btn btn-sm btn-outline-primary">Mark as read</button></form><?php else:?><span class="small text-muted">Read</span><?php endif;?></div></div><?php endforeach;if(!$rows):?><div class="col-12"><div class="cardx empty">No notifications.</div></div><?php endif;?></div><?php break;
case 'users':
    $rows=$pdo->query('SELECT id,full_name,email,role,created_at FROM users ORDER BY full_name')->fetchAll();?><div class="toolbar"><div><h5 class="mb-0">User Accounts</h5><small class="text-muted">Staff-only account management.</small></div><button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#userModal"><i class="bi bi-person-plus me-1"></i>Add User</button></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th>Action</th></tr></thead><tbody><?php foreach($rows as $u):?><tr><td><?=e($u['full_name'])?></td><td><?=e($u['email'])?></td><td><?=e(roleLabel($u['role']))?></td><td><?=fmtDate($u['created_at'])?></td><td><?php if((int)$u['id']!==$uid):?><form method="post" onsubmit="return confirm('Delete this user?')"><?=csrfField()?><input type="hidden" name="action" value="delete_user"><input type="hidden" name="id" value="<?=$u['id']?>"><button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button></form><?php else:?><span class="text-muted">Current user</span><?php endif;?></td></tr><?php endforeach;?></tbody></table></div></div><?php require __DIR__ . '/modals/user_modal.php'; ?><?php break;
case 'audit':
    $rows=$pdo->query('SELECT a.*,u.full_name,u.role FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 300')->fetchAll();?><div class="toolbar"><div><h5 class="mb-0">Activity Audit Logs</h5><small class="text-muted">Staff-only accountability trail.</small></div></div><div class="cardx table-card"><div class="table-responsive"><table class="table"><thead><tr><th>Time</th><th>User</th><th>Role</th><th>Action</th><th>Table</th><th>Record</th><th>Description</th></tr></thead><tbody><?php foreach($rows as $r):?><tr><td><?=fmtDate($r['created_at'],'M d, Y h:i A')?></td><td><?=e($r['full_name']??'System')?></td><td><?=e(roleLabel($r['role']??''))?></td><td><?=e($r['action'])?></td><td><?=e($r['table_name'])?></td><td>#<?=e($r['record_id'])?></td><td><?=e($r['description'])?></td></tr><?php endforeach;?></tbody></table></div></div><?php break;
case 'profile':
    ?><div class="row g-3"><div class="col-lg-4"><div class="cardx p-4 text-center"><div class="avatar mx-auto mb-3" style="width:80px;height:80px;font-size:30px"><?=e(strtoupper(substr($me['full_name'],0,1)))?></div><h4><?=e($me['full_name'])?></h4><div><?=badge($role==='staff'?'read':$role)?></div><p class="text-muted mt-3 mb-0">Account created <?=fmtDate($me['created_at'])?></p></div></div><div class="col-lg-8"><div class="cardx p-4"><h5>Profile Management</h5><form method="post" class="mt-3"><?=csrfField()?><input type="hidden" name="action" value="save_profile"><div class="row g-3"><div class="col-md-6"><label class="form-label">Full Name</label><input class="form-control" name="full_name" value="<?=e($me['full_name'])?>" required></div><div class="col-md-6"><label class="form-label">Email</label><input class="form-control" type="email" name="email" value="<?=e($me['email'])?>" required></div><div class="col-md-6"><label class="form-label">Role</label><input class="form-control" value="<?=e(roleLabel($role))?>" disabled></div><div class="col-md-6"><label class="form-label">New Password</label><input class="form-control" type="password" name="password" minlength="6" placeholder="Leave blank to keep current"></div></div><button class="btn btn-primary mt-4">Save Profile</button></form></div></div></div><?php break;
endswitch;
?>
</section></main><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script><script>
const sb=document.getElementById('sidebar'),main=document.getElementById('main');document.getElementById('toggle').onclick=()=>{sb.classList.toggle('collapsed');main.classList.toggle('expanded');};
function editItem(x){document.getElementById('item_action').value='update_item';document.getElementById('item_id').value=x.id;document.getElementById('itemTitle').textContent='Edit Hardware Asset';for(const [id,key] of [['item_asset','asset_code'],['item_name','item_name'],['item_category','category_id'],['item_serial','serial_number'],['item_brand','brand'],['item_model','model'],['item_quantity','quantity'],['item_condition','condition_status'],['item_availability','availability_status'],['item_description','description']])document.getElementById(id).value=x[key]??'';bootstrap.Modal.getOrCreateInstance(document.getElementById('itemModal')).show();}
function editCat(x){document.getElementById('cat_action').value='update_category';document.getElementById('cat_id').value=x.id;document.getElementById('catTitle').textContent='Edit Category';document.getElementById('cat_name').value=x.name;document.getElementById('cat_desc').value=x.description??'';bootstrap.Modal.getOrCreateInstance(document.getElementById('catModal')).show();}
function editBorrower(x){document.getElementById('borrower_action').value='update_borrower';document.getElementById('borrower_id').value=x.id;document.getElementById('borrowerTitle').textContent='Edit Borrower';document.getElementById('borrower_name').value=x.borrower_name;document.getElementById('borrower_student').value=x.student_id;document.getElementById('borrower_email').value=x.email??'';document.getElementById('borrower_contact').value=x.contact_number??'';document.getElementById('borrower_department').value=x.department??'';bootstrap.Modal.getOrCreateInstance(document.getElementById('borrowerModal')).show();}
</script></body></html>
    