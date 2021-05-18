from unittest import mock

from detect_secrets_stream.notification.vmt_report import VmtReport


class TestVmtReport:

    @mock.patch('detect_secrets_stream.notification.vmt_report.BoxClient')
    @mock.patch('detect_secrets_stream.notification.vmt_report.GdReportGenerator')
    def test_send_csv(self, mock_gd_report_generator, mock_box_client):
        mock_box_client.return_value = mock_box_client_inst = mock.MagicMock()
        box_folder_id = 'fake_box_folder_id'

        vmt_report = VmtReport()
        vmt_report.send_csv(box_folder_id, org_set_filter='test')

        mock_box_client.assert_called()
        mock_box_client_inst.upload_file.assert_called_with(box_folder_id, mock.ANY)
        mock_gd_report_generator.assert_called()
        mock_gd_report_generator.return_value.generate_csv_from_db.assert_called_with(
            mock.ANY, include_private_repo_tokens=True, org_set_filter='test',
        )

    @mock.patch('detect_secrets_stream.notification.vmt_report.GdReportGenerator')
    @mock.patch('detect_secrets_stream.notification.vmt_report.connect_db', return_value='connect_db')
    @mock.patch('detect_secrets_stream.notification.vmt_report.truncate_vmt_report')
    def test_generate_db_report(self, mock_truncate_vmt_report, mock_connect_db, mock_gd_report_generator):
        vmt_report = VmtReport()
        vmt_report.generate_db_report()

        mock_connect_db.assert_called()
        mock_truncate_vmt_report.assert_called_once_with('connect_db')

        mock_gd_report_generator.assert_called_once_with(
            include_security_focals=True,
            include_repo_visibility=True,
        )
        mock_gd_report_generator.return_value.generate_vmt_report_in_db.assert_called_with(
            include_private_repo_tokens=True,
        )
