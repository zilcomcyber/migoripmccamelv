<?php
require_once '../config.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

try {
    $method = $_SERVER['REQUEST_METHOD'];

    if ($method === 'GET') {
        $parent_id = intval($_GET['parent_id'] ?? 0);
        $offset = intval($_GET['offset'] ?? 0);
        $limit = intval($_GET['limit'] ?? 5);

        if (!$parent_id) {
            json_response(['success' => false, 'message' => 'Parent comment ID required'], 400);
        }

        // Get user's IP address for pending comments
        $user_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '127.0.0.1';

        $sql = "SELECT f.*, 
                       a.name as admin_name,
                       a.email as admin_email,
                       CASE WHEN f.user_ip = ? AND f.status = 'pending' THEN 1 ELSE 0 END as is_user_pending,
                       CASE WHEN f.subject = 'Admin Response' OR f.citizen_name = '' OR f.citizen_name IS NULL THEN 1 ELSE 0 END as is_admin_comment
                FROM feedback f
                LEFT JOIN admins a ON f.responded_by = a.id 
                WHERE f.parent_comment_id = ? 
                AND (f.status IN ('approved', 'reviewed', 'responded') OR (f.status = 'pending' AND f.user_ip = ?))
                ORDER BY f.created_at ASC
                LIMIT ? OFFSET ?";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$user_ip, $parent_id, $user_ip, $limit, $offset]);
        $replies = $stmt->fetchAll();

        // Format replies for display
        $formatted_replies = [];
        foreach ($replies as $reply) {
            $reply_is_admin = isset($reply['is_admin_comment']) ? 
                $reply['is_admin_comment'] : 
                (strpos($reply['id'], 'admin_') === 0 || $reply['subject'] === 'Admin Response' || empty($reply['citizen_name']));
            
            $reply_display_name = $reply_is_admin ? 
                ($reply['admin_name'] ?? 'Admin') : 
                $reply['citizen_name'];

            $reply_is_user_pending = isset($reply['is_user_pending']) ? $reply['is_user_pending'] : false;

            $formatted_replies[] = [
                'id' => $reply['id'],
                'message' => $reply['message'],
                'created_at' => $reply['created_at'],
                'display_name' => $reply_display_name,
                'is_admin' => $reply_is_admin,
                'is_user_pending' => $reply_is_user_pending,
                'time_ago' => time_ago($reply['created_at'])
            ];
        }

        // Get remaining count
        $remaining_sql = "SELECT COUNT(*) FROM feedback 
                         WHERE parent_comment_id = ? 
                         AND status IN ('approved', 'reviewed', 'responded')";
        $stmt = $pdo->prepare($remaining_sql);
        $stmt->execute([$parent_id]);
        $total_count = $stmt->fetchColumn();
        $remaining = max(0, $total_count - ($offset + $limit));

        json_response([
            'success' => true,
            'replies' => $formatted_replies,
            'remaining' => $remaining,
            'has_more' => $remaining > 0
        ]);

    } else {
        json_response(['success' => false, 'message' => 'Method not allowed'], 405);
    }

} catch (Exception $e) {
    error_log("Load more replies API Error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to load replies'], 500);
}

function time_ago($datetime) {
    $time = time() - strtotime($datetime);

    if ($time < 60) return 'just now';
    if ($time < 3600) return floor($time / 60) . ' minutes ago';
    if ($time < 86400) return floor($time / 3600) . ' hours ago';
    if ($time < 2592000) return floor($time / 86400) . ' days ago';
    if ($time < 31536000) return floor($time / 2592000) . ' months ago';
    return floor($time / 31536000) . ' years ago';
}
?>
