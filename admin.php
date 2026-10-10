<?php
ini_set('session.use_strict_mode','1');
ini_set('session.cookie_httponly','1');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ini_set('session.cookie_secure','1');
session_name('online_magazin_admin'); session_start();
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY'); header('Cache-Control: no-store');
function h($v) { return htmlspecialchars((string)$v,ENT_QUOTES,'UTF-8'); }
function f($k) { return isset($_POST[$k]) && is_string($_POST[$k]) ? trim($_POST[$k]) : ''; }
function q($s,$a=array()) { global $db; $r=$db->prepare($s); $r->execute($a); return $r; }
function back() { header('Location: admin.php'); exit; }
function csrf() { echo '<input type="hidden" name="csrf" value="'.h($_SESSION['csrf']).'">'; }
if (empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32));
$c=require __DIR__.'/config.php';
try {
 $db=new PDO('mysql:host='.$c['host'].';port='.$c['port'].';dbname='.$c['database'].';charset=utf8mb4',$c['user'],$c['password'],array(PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false));
 q('SELECT admin_id FROM shop_admins LIMIT 1'); q('SELECT customer_id FROM shop_customer_access LIMIT 1'); q('SELECT product_id FROM shop_product_hidden LIMIT 1');
} catch (PDOException $e) { http_response_code(503); exit('Алдымен admin.sql және manage.sql файлдарын internet_shop_web базасына импорттаңыз. config.php баптауын тексеріңіз.'); }
$admin=!empty($_SESSION['aid']) ? q('SELECT * FROM shop_admins WHERE admin_id=?',array($_SESSION['aid']))->fetch() : null;
if ($admin && (!isset($_SESSION['version']) || !hash_equals($admin['password_hash'],$_SESSION['version']))) { unset($_SESSION['aid']); $admin=null; }
$error=''; $savedFile=null;
if ($_SERVER['REQUEST_METHOD']==='POST') {
 try {
  if (!hash_equals($_SESSION['csrf'],f('csrf'))) throw new Exception('Бетті жаңартып, қайта көріңіз. Фото сервердің жүктеу шегінен аспауы керек.');
  $action=f('action');
  if ($action==='login') {
   $u=q('SELECT * FROM shop_admins WHERE username=?',array(f('username')))->fetch();
   if ($u && (int)$u['locked_until']>time()) throw new Exception('Бірнеше қате әрекеттен кейін кіру уақытша тоқтатылды. 5 минуттан кейін көріңіз.');
   if (!$u || !password_verify(f('password'),$u['password_hash'])) {
    if ($u) q('UPDATE shop_admins SET locked_until=IF(failed_attempts>=4,UNIX_TIMESTAMP()+300,locked_until), failed_attempts=IF(failed_attempts>=4,0,failed_attempts+1) WHERE admin_id=?',array($u['admin_id']));
    throw new Exception('Логин немесе құпиясөз қате.');
   }
   q('UPDATE shop_admins SET failed_attempts=0,locked_until=0 WHERE admin_id=?',array($u['admin_id']));
   session_regenerate_id(true); $_SESSION['aid']=$u['admin_id']; $_SESSION['version']=$u['password_hash']; $_SESSION['csrf']=bin2hex(random_bytes(32)); back();
  }
  if (!$admin) { http_response_code(403); throw new Exception('Алдымен админ аккаунтына кіріңіз.'); }
  if ($action==='logout') { $_SESSION=array(); session_regenerate_id(true); back(); }
  if ($action==='hide_product') {
   $id=filter_var(f('id'),FILTER_VALIDATE_INT);
   $db->beginTransaction();
   if (!$id || !q('SELECT product_id FROM products WHERE product_id=? FOR UPDATE',array($id))->fetch()) throw new Exception('Тауар табылмады.');
   q('INSERT IGNORE INTO shop_product_hidden (product_id) VALUES (?)',array($id));
   $db->commit(); $_SESSION['notice']='Тауар дүкеннен өшірілді. Бұрынғы тапсырыстарда сақталады.'; back();
  }
  if (in_array($action,array('block_customer','unblock_customer','delete_customer'))) {
   $id=filter_var(f('id'),FILTER_VALIDATE_INT);
   $db->beginTransaction();
   if (!$id || !q('SELECT customer_id FROM customers WHERE customer_id=? FOR UPDATE',array($id))->fetch()) throw new Exception('Клиент табылмады.');
   $access=q('SELECT * FROM shop_customer_access WHERE customer_id=?',array($id))->fetch();
   if ($access && $access['deleted']) throw new Exception('Клиент бұрын өшірілген.');
   if ($action==='delete_customer') {
    q('INSERT INTO shop_customer_access (customer_id,blocked,deleted) VALUES (?,1,1) ON DUPLICATE KEY UPDATE blocked=1,deleted=1',array($id));
    q('DELETE FROM shop_accounts WHERE customer_id=?',array($id));
    q('UPDATE customers SET full_name=?,email=?,phone=NULL,address=NULL WHERE customer_id=?',array('Өшірілген клиент','deleted-'.$id.'-'.bin2hex(random_bytes(8)).'@invalid.local',$id));
    q('UPDATE orders SET delivery_address=? WHERE customer_id=?',array('Өшірілген',$id));
    $_SESSION['notice']='Клиент аккаунты мен жеке мәліметтері өшірілді. Тапсырыс тарихы сақталды.';
   } else {
    $b=$action==='block_customer'?1:0;
    q('INSERT INTO shop_customer_access (customer_id,blocked,deleted) VALUES (?,?,0) ON DUPLICATE KEY UPDATE blocked=VALUES(blocked)',array($id,$b));
    $_SESSION['notice']=$b?'Клиент бұғатталды.':'Клиент бұғаттан шығарылды.';
   }
   $db->commit(); back();
  }
  if ($action==='password') {
   if (!password_verify(f('old_password'),$admin['password_hash'])) throw new Exception('Қазіргі құпиясөз қате.');
   $p=f('new_password');
   if (strlen($p)<10 || strlen($p)>72 || $p!==f('confirm')) throw new Exception('Жаңа құпиясөз 10–72 байт болып, қайталаумен сәйкес келуі керек.');
   $hash=password_hash($p,PASSWORD_DEFAULT); q('UPDATE shop_admins SET password_hash=? WHERE admin_id=?',array($hash,$admin['admin_id']));
   session_regenerate_id(true); $_SESSION['version']=$hash; $_SESSION['csrf']=bin2hex(random_bytes(32)); $_SESSION['notice']='Құпиясөз өзгертілді.'; back();
  }
  if ($action==='product') {
   $name=f('name'); $description=f('description'); $price=f('price'); $stock=filter_var(f('stock'),FILTER_VALIDATE_INT); $category=filter_var(f('category'),FILTER_VALIDATE_INT);
   if ($name==='' || mb_strlen($name)>150 || mb_strlen($description)>5000) throw new Exception('Атауы 1–150, сипаттамасы 5000 таңбаға дейін болуы керек.');
   if (!preg_match('/^\d{1,10}(\.\d{1,2})?$/D',$price) || (float)$price<=0) throw new Exception('Бағаны дұрыс енгізіңіз, мысалы: 5000 немесе 5000.50.');
   if ($stock===false || $stock<0 || $stock>1000000) throw new Exception('Саны 0–1000000 аралығында болуы керек.');
   if (!$category || !q('SELECT category_id FROM categories WHERE category_id=?',array($category))->fetch()) throw new Exception('Санатты таңдаңыз.');
   $url=null;
   if (isset($_FILES['photo']) && $_FILES['photo']['error']!==UPLOAD_ERR_NO_FILE) {
    $photo=$_FILES['photo'];
    if (is_array($photo['error']) || $photo['error']!==UPLOAD_ERR_OK || $photo['size']>2*1024*1024 || !is_uploaded_file($photo['tmp_name'])) throw new Exception('Фото жүктелмеді. JPG немесе PNG, ең көбі 2 МБ таңдаңыз.');
    $info=@getimagesize($photo['tmp_name']);
    if (!$info || !in_array($info[2],array(IMAGETYPE_JPEG,IMAGETYPE_PNG)) || $info[0]>6000 || $info[1]>6000) throw new Exception('Тек JPG/PNG сурет қабылданады (ең көбі 6000×6000).');
    $dir=__DIR__.'/images/admin-products';
    if (!is_dir($dir) && !mkdir($dir,0755,true)) throw new Exception('Сурет папкасын жасау мүмкін болмады.');
    $url='images/admin-products/'.bin2hex(random_bytes(16)).($info[2]===IMAGETYPE_JPEG ? '.jpg' : '.png');
    $savedFile=__DIR__.'/'.$url;
    if (!move_uploaded_file($photo['tmp_name'],$savedFile)) { $savedFile=null; throw new Exception('Суретті сақтау мүмкін болмады.'); }
   }
   q('INSERT INTO products (product_name,category_id,description,price,stock,image_url) VALUES (?,?,?,?,?,?)',array($name,$category,$description,$price,$stock,$url));
   $savedFile=null; $_SESSION['notice']='Тауар қосылды! Оны дүкеннен көре аласыз.'; back();
  }
 } catch (Exception $e) { if ($db->inTransaction()) $db->rollBack(); if ($savedFile && is_file($savedFile)) unlink($savedFile); $error=$e instanceof PDOException ? 'Базаға сақтау орындалмады. Қайта көріңіз.' : $e->getMessage(); }
}
$notice=isset($_SESSION['notice']) ? $_SESSION['notice'] : ''; unset($_SESSION['notice']);
?>
<!doctype html><html lang="kk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Админ — Онлайн магазин</title><link rel="stylesheet" href="style.css"><style>.admin-wrap{max-width:900px;margin:32px auto;padding:0 20px}.panel{background:white;border:1px solid #ddd;border-radius:18px;padding:24px;margin:20px 0}.admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}label{display:block;margin:12px 0}input,select,textarea{display:block;width:100%;box-sizing:border-box;margin-top:7px;padding:12px;border:1px solid #ccc;border-radius:8px}textarea{min-height:100px}.admin-head{display:flex;justify-content:space-between;align-items:center;gap:16px}.admin-head form{margin:0}.admin-list{display:grid;gap:10px}.admin-item{display:flex;justify-content:space-between;border-bottom:1px solid #eee;padding:12px 0;gap:15px}@media(max-width:600px){.admin-grid{grid-template-columns:1fr}.admin-head{flex-wrap:wrap}}</style></head><body><div class="admin-wrap"><div class="admin-head"><h2>Онлайн магазин · Админ</h2><a href="index.php">Дүкенге өту ↗</a><?php if($admin): ?><form method="post"><?php csrf(); ?><input type="hidden" name="action" value="logout"><button>Шығу</button></form><?php endif; ?></div>
<?php if($notice): ?><div class="notice" role="status"><?=h($notice)?></div><?php endif; ?><?php if($error): ?><div class="error" role="alert"><?=h($error)?></div><?php endif; ?>
<?php if(!$admin): ?><section class="panel" style="max-width:420px;margin:40px auto"><h1>Админ аккаунтына кіру</h1><form method="post"><?php csrf(); ?><input type="hidden" name="action" value="login"><label>Логин<input name="username" autocomplete="username" required maxlength="80"></label><label>Құпиясөз<input type="password" name="password" autocomplete="current-password" required maxlength="72"></label><button class="wide">Кіру</button></form></section>
<?php else: $categories=q('SELECT * FROM categories ORDER BY category_id')->fetchAll(); ?>
<section class="panel"><h1>Жаңа тауар қосу</h1><p>Мәліметтерді толтырып, фотоны компьютерден таңдаңыз.</p><form method="post" enctype="multipart/form-data"><?php csrf(); ?><input type="hidden" name="action" value="product"><label>Тауар атауы<input name="name" required maxlength="150" value="<?=h(f('name'))?>" placeholder="Мысалы: Сымсыз тышқан"></label><label>Санат<select name="category" required><option value="">Санатты таңдаңыз</option><?php foreach($categories as $cat): ?><option value="<?=(int)$cat['category_id']?>" <?=f('category')==(string)$cat['category_id']?'selected':''?>><?=h($cat['category_name'])?></option><?php endforeach; ?></select></label><div class="admin-grid"><label>Бағасы (₸)<input name="price" type="number" min="0.01" max="9999999999.99" step="0.01" required value="<?=h(f('price'))?>"></label><label>Қоймадағы саны<input name="stock" type="number" min="0" max="1000000" required value="<?=h(f('stock')===''?'1':f('stock'))?>"></label></div><label>Сипаттамасы<textarea name="description" maxlength="5000"><?=h(f('description'))?></textarea></label><label>Тауар фотосы (JPG/PNG, 2 МБ дейін)<input type="file" name="photo" accept="image/jpeg,image/png"></label><p>Фото міндетті емес. Қате болса, фотоны қайта таңдаңыз.</p><button>Тауарды сақтау</button></form></section>
<section class="panel"><h2>Тауарларды басқару</h2><p>Өшіру тауарды каталог пен себеттен алып тастайды. Бұрынғы тапсырыстар сақталады.</p><div class="admin-list"><?php foreach(q('SELECT p.* FROM products p LEFT JOIN shop_product_hidden h ON h.product_id=p.product_id WHERE h.product_id IS NULL ORDER BY p.product_id DESC')->fetchAll() as $p): ?><div class="admin-item"><div><b><?=h($p['product_name'])?></b><p><?=h($p['price'])?> ₸ · <?=(int)$p['stock']?> дана</p></div><form method="post" onsubmit="return confirm('Тауарды дүкеннен өшіресіз бе?')"><?php csrf(); ?><input type="hidden" name="action" value="hide_product"><input type="hidden" name="id" value="<?=(int)$p['product_id']?>"><button>Өшіру</button></form></div><?php endforeach; ?></div></section>
<section class="panel"><h2>Клиенттер</h2><p>Бұғатталған клиент кіре алмайды және тапсырыс бере алмайды. Өшіру аккаунт пен жеке мәліметтерді жояды; тапсырыс тарихын сақтайды.</p>
<?php $clients=q('SELECT c.*,COALESCE(a.blocked,0) blocked FROM customers c LEFT JOIN shop_customer_access a ON a.customer_id=c.customer_id WHERE COALESCE(a.deleted,0)=0 ORDER BY c.customer_id DESC')->fetchAll(); if(!$clients): ?><p>Клиенттер жоқ.</p><?php endif; foreach($clients as $c): ?>
<div class="admin-item" style="flex-wrap:wrap"><div><b>#<?=(int)$c['customer_id']?> · <?=h($c['full_name'])?></b><p><?=h($c['email'])?> · <?=h($c['phone'])?></p><p><?=h($c['address'])?></p><strong><?=$c['blocked']?'Бұғатталған':'Белсенді'?></strong></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><form method="post"><?php csrf(); ?><input type="hidden" name="action" value="<?=$c['blocked']?'unblock_customer':'block_customer'?>"><input type="hidden" name="id" value="<?=(int)$c['customer_id']?>"><button><?=$c['blocked']?'Бұғаттан шығару':'Бұғаттау'?></button></form><form method="post" onsubmit="return confirm('Клиент аккаунты мен жеке мәліметтері өшіріледі. Жалғастырасыз ба?')"><?php csrf(); ?><input type="hidden" name="action" value="delete_customer"><input type="hidden" name="id" value="<?=(int)$c['customer_id']?>"><button>Өшіру</button></form></div></div><?php endforeach; ?></section>
<details class="panel"><summary>Админ құпиясөзін өзгерту</summary><form method="post"><?php csrf(); ?><input type="hidden" name="action" value="password"><label>Қазіргі құпиясөз<input type="password" name="old_password" autocomplete="current-password" required></label><label>Жаңа құпиясөз<input type="password" name="new_password" minlength="10" maxlength="72" autocomplete="new-password" required></label><label>Қайта енгізіңіз<input type="password" name="confirm" minlength="10" maxlength="72" autocomplete="new-password" required></label><button>Құпиясөзді сақтау</button></form></details>
<?php endif; ?></div></body></html>
