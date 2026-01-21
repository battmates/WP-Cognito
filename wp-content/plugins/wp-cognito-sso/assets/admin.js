jQuery(function ($) {
  $('#wcsso-add-role-mapping').on('click', function () {
    var $table = $('#wcsso-role-mapping-table tbody');
    var $row = $table.find('tr').first().clone();
    $row.find('input').val('');
    $row.find('select').val('');
    $table.append($row);
  });

  $(document).on('click', '.wcsso-remove-row', function () {
    var $rows = $('#wcsso-role-mapping-table tbody tr');
    if ($rows.length <= 1) {
      $rows.find('input').val('');
      $rows.find('select').val('');
      return;
    }
    $(this).closest('tr').remove();
  });
});
