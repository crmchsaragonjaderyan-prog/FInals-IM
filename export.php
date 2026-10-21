<?php
require_once __DIR__.'/connection.php';require_once __DIR__.'/classes/Helpers.php';require_once __DIR__.'/backend/middleware/RoleMiddleware.php';require_permission($auth,'export');
header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename=it_lab_inventory_'.date('Y-m-d').'.csv');
$out=fopen('php://output','w');fputcsv($out,['Asset Code','Item Name','Category','Brand','Model','Serial Number','Quantity','Condition','Availability']);
$rows=$pdo->query("SELECT h.*,c.name category_name FROM hardware_items h JOIN categories c ON c.id=h.category_id ORDER BY h.id")->fetchAll();
foreach($rows as $r)fputcsv($out,[$r['asset_code'],$r['item_name'],$r['category_name'],$r['brand'],$r['model'],$r['serial_number'],$r['quantity'],$r['condition_status'],$r['availability_status']]);fclose($out);exit;
